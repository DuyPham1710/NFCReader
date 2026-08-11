//
//  SODVerifier.swift
//  NFCReaderSDK
//
//  Xác thực chữ ký số trên EF.SOD theo chuỗi tin cậy:
//    1. Verify DS Certificate bằng CSCA Certificate (từ masterList.pem)
//    2. Verify chữ ký trên SignedData (SOD) bằng Public Key của DS Certificate
//
//  Sử dụng OpenSSL C-API vì việc verify PKCS#7 / X.509 bằng Swift thuần
//  cực kỳ phức tạp và dễ sai. OpenSSL đã có sẵn trong project (dùng cho CA).
//

import Foundation
import OpenSSL

@available(iOS 13, macOS 10.15, *)
public class SODVerifier {
    
    /// Verify toàn bộ chuỗi tin cậy của SOD:
    ///   Bước 1: DS Certificate có hợp lệ (được ký bởi CSCA trong masterList.pem)?
    ///   Bước 2: Chữ ký trên SOD có hợp lệ (được ký bởi DS Certificate)?
    ///
    /// - Parameters:
    ///   - sodData: Dữ liệu thô (raw bytes) của file EF.SOD đọc từ chip
    ///   - masterListPEM: Nội dung file masterList.pem (chứa các CSCA Certificates)
    /// - Returns: Tuple xác nhận trạng thái của Bước 1 (cscaVerified) và Bước 2 (signatureVerified)
    public static func verify(sodData: [UInt8], masterListPEM: String) -> (cscaVerified: Bool, signatureVerified: Bool) {
        
        // ============================
        // Parse SOD bytes thành PKCS#7
        // ============================
        
        // SOD raw data bắt đầu bằng TLV wrapper (tag 0x77), ta cần bỏ wrapper để lấy PKCS#7 DER
        let derBytes: [UInt8]
        do {
            derBytes = try extractPKCS7DER(from: sodData)
        } catch {
            print("[SODVerifier] Không thể trích xuất PKCS#7 DER từ SOD: \(error)")
            return (false, false)
        }
        
        // Đọc PKCS#7 từ DER bytes
        var derPtr: UnsafePointer<UInt8>? = UnsafePointer(derBytes)
        guard let pkcs7 = d2i_PKCS7(nil, &derPtr, derBytes.count) else {
            print("[SODVerifier] Không thể parse PKCS#7 từ SOD DER. OpenSSL: \(OpenSSLUtils.getOpenSSLError())")
            return (false, false)
        }
        defer { PKCS7_free(pkcs7) }
        
        // Log DS Cert (Base64) để gửi lên C06
        extractAndLogDSCertificate(from: pkcs7)
        
        // =============================================
        // Bước 1: Xây dựng Trust Store từ masterList.pem
        // =============================================
        guard let store = X509_STORE_new() else {
            print("[SODVerifier] Không thể tạo X509_STORE")
            return (false, false)
        }
        defer { X509_STORE_free(store) }
        
        // Load các CSCA certificates từ PEM string vào store
        let cscaCount = loadCertificatesIntoStore(store: store, pemString: masterListPEM)
        guard cscaCount > 0 else {
            print("[SODVerifier] Không tìm thấy CSCA certificate nào trong masterList.pem")
            return (false, false)
        }
 //       print("[SODVerifier] Đã load \(cscaCount) CSCA certificate(s) vào Trust Store.")
        
        // =============================================
        // Bước 2: Verify PKCS#7 signature + certificate chain
        // =============================================
        // PKCS7_verify sẽ tự động:
        //   - Trích xuất DS Certificate từ SignerInfo
        //   - Verify DS Cert bằng Trust Store (chứa CSCA)
        //   - Verify chữ ký trên SignedData bằng DS Cert public key
        //
        // Flag PKCS7_NOINTERN: Không tìm signer cert bên ngoài, chỉ dùng cert nhúng trong PKCS#7
        // Flag PKCS7_NOSIGS: (KHÔNG dùng) - ta muốn verify signature
        
        // Tạo BIO rỗng cho content (PKCS#7 attached signature - content nằm trong PKCS#7 rồi)
        // Lần 1: Thử Verify CẢ Bước 1 và Bước 2 (Cờ 0)
        let contentBio = BIO_new(BIO_s_mem())
        defer { BIO_free(contentBio) }
        
        let resultFull = PKCS7_verify(pkcs7, nil, store, nil, contentBio, 0)
        
        if resultFull == 1 {
            return (cscaVerified: true, signatureVerified: true)
        }
        
        // Nếu Lần 1 thất bại (Thường do thiếu CSCA của VN), ta bỏ qua lỗi cũ
        _ = OpenSSLUtils.getOpenSSLError() // Clear error queue
        
        // Lần 2: Thử Verify CHỈ Bước 2 (Cờ PKCS7_NOVERIFY = 0x20)
        // Bỏ qua việc check chứng thư (Bước 1), chỉ kiểm tra chữ ký SOD có khớp với DS Public Key không
        let PKCS7_NOVERIFY: Int32 = 0x20
        let resultSigOnly = PKCS7_verify(pkcs7, nil, store, nil, contentBio, PKCS7_NOVERIFY)
        
        if resultSigOnly == 1 {
            return (cscaVerified: false, signatureVerified: true)
        } else {
            let errMsg = OpenSSLUtils.getOpenSSLError()
            print("[SODVerifier] ❌ PKCS#7 verify chữ ký thất bại: \(errMsg)")
            return (cscaVerified: false, signatureVerified: false)
        }
    }
    
    // MARK: - Private Helpers
    
    /// Trích xuất phần PKCS#7 DER từ SOD raw bytes.
    /// SOD raw data có dạng: Tag(0x77) + Length + [PKCS#7 DER content]
    /// Ta cần bỏ lớp wrapper ngoài cùng (tag 0x77) để lấy PKCS#7 DER thuần.
    private static func extractPKCS7DER(from sodData: [UInt8]) throws -> [UInt8] {
        guard !sodData.isEmpty else {
            throw NFCReaderError.responseError("SOD data rỗng")
        }
        
        // Bỏ qua TLV tag đầu tiên (thường là 0x77 hoặc 0x6E)
        var offset = 0
        let tag = sodData[offset]
        offset += 1
        
        // Đọc length
        let lengthResult = try asn1Length(Array(sodData[offset...]))
        offset += lengthResult.offset
        
        // Phần còn lại chính là PKCS#7 DER
        let pkcs7DER = Array(sodData[offset...])
        
        print("[SODVerifier] Extracted PKCS#7 DER: tag=0x\(String(format: "%02X", tag)), DER size=\(pkcs7DER.count) bytes")
        
        // TODO: In ra Base64 để user tiện kiểm tra DS Certificate bằng công cụ bên ngoài
        print("\n================= DS CERTIFICATE (PKCS#7) =================")
        print("Lưu đoạn chữ dưới đây thành file 'sod.p7b' để xem DS Certificate:")
        print("-----BEGIN PKCS7-----")
        
        let base64String = Data(pkcs7DER).base64EncodedString()
        var index = base64String.startIndex
        while index < base64String.endIndex {
            let nextIndex = base64String.index(index, offsetBy: 64, limitedBy: base64String.endIndex) ?? base64String.endIndex
            print(String(base64String[index..<nextIndex]))
            index = nextIndex
        }
        
        print("-----END PKCS7-----")
        print("==============================================================\n")
        
        return pkcs7DER
    }
    
    /// Load tất cả X.509 certificates từ chuỗi PEM vào X509_STORE.
    /// Trả về số lượng cert đã load thành công.
    private static func loadCertificatesIntoStore(store: OpaquePointer, pemString: String) -> Int {
        var count = 0
        
        // Tạo BIO từ PEM string
        guard let bio = BIO_new_mem_buf(pemString, Int32(pemString.utf8.count)) else {
            return 0
        }
        defer { BIO_free(bio) }
        
        // Đọc từng certificate trong PEM (file có thể chứa nhiều cert nối tiếp)
        while let cert = PEM_read_bio_X509(bio, nil, nil, nil) {
            if X509_STORE_add_cert(store, cert) == 1 {
                count += 1
            }
            // Không free cert ở đây vì X509_STORE_add_cert đã tăng reference count
            // và store sẽ tự free khi bị deallocate
        }
        
        return count
    }
    
    // Trích xuất riêng DS Certificate từ PKCS#7
    /// Lấy DS Certificate ra khỏi cục PKCS#7 và in ra dạng Base64 PEM.
    /// App sẽ gửi lên C06 để verify.
    ///
    /// Cấu trúc ASN.1 của PKCS#7 SignedData:
    /// SEQUENCE (root)
    ///   ├─ OBJECT: pkcs7-signedData
    ///   └─ [0] cont
    ///       └─ SEQUENCE (SignedData)
    ///           ├─ INTEGER (version)
    ///           ├─ SET (digestAlgorithms)
    ///           ├─ SEQUENCE (encapContentInfo - chứa Hash list)
    ///           ├─ [0] cont (certificates - DS Cert nằm ở đây!)
    ///           │   └─ SEQUENCE (DS Certificate)
    ///           └─ SET (signerInfos - chứa chữ ký)
    private static func extractAndLogDSCertificate(from pkcs7: UnsafeMutablePointer<PKCS7>) {
        // Chuyển PKCS7 struct thành DER bytes để parse bằng ASN1Node
        var derOut: UnsafeMutablePointer<UInt8>? = nil
        let derLen = i2d_PKCS7(pkcs7, &derOut)
        guard derLen > 0, let derData = derOut else {
            print("[SODVerifier] ⚠️ Không thể encode PKCS#7 sang DER để trích xuất DS Cert")
            return
        }
        defer { CRYPTO_free(derData, "", 0) }
        
        let pkcs7Bytes = Array(UnsafeBufferPointer(start: derData, count: Int(derLen)))
        
        // Parse ASN.1 tree
        guard let root = try? ASN1Node.parse(pkcs7Bytes) else {
            print("[SODVerifier] ⚠️ Không thể parse ASN.1 của PKCS#7")
            return
        }
        
        // Đi theo cây ASN.1: root > [0] cont > SEQUENCE (SignedData)
        guard root.children.count >= 2,
              root.children[1].children.count >= 1 else {
            print("[SODVerifier] ⚠️ Cấu trúc PKCS#7 không đúng chuẩn")
            return
        }
        let signedData = root.children[1].children[0] // SEQUENCE (SignedData)
        
        // Tìm node [0] cont (tag 0xA0) chứa danh sách certificates
        var certNode: ASN1Node? = nil
        for child in signedData.children {
            if child.tag == 0xA0 { // context [0] = certificates
                if child.children.count > 0 {
                    certNode = child.children[0] // DS Certificate (SEQUENCE đầu tiên)
                }
                break
            }
        }
        
        guard let dsCert = certNode else {
            print("[SODVerifier] ⚠️ Không tìm thấy DS Certificate trong PKCS#7")
            return
        }
        
        // fullBytes chứa toàn bộ TLV (Tag + Length + Value) = DER encoding hoàn chỉnh của cert
        let certDER = dsCert.fullBytes
        let base64String = Data(certDER).base64EncodedString()
        
        // In ra DS Certificate riêng biệt (chuẩn PEM)
        print("\n================= DS CERTIFICATE (Riêng) =================")
        print("DS Certificate trích từ SOD, dùng để gửi lên C06 xác thực.")
        print("-----BEGIN CERTIFICATE-----")
        
        var index = base64String.startIndex
        while index < base64String.endIndex {
            let nextIndex = base64String.index(index, offsetBy: 64, limitedBy: base64String.endIndex) ?? base64String.endIndex
            print(String(base64String[index..<nextIndex]))
            index = nextIndex
        }
        
        print("-----END CERTIFICATE-----")
        print("Kích thước: \(certDER.count) bytes (DER)")
        print("==============================================================\n")
    }
}
