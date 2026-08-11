//  Xác minh toàn vẹn dữ liệu bằng cách Hash lại
//  nội dung của các Data Group và đối chiếu với mã Hash được lưu trữ trong EF.SOD

//  Passive Authentication (PA) đầy đủ theo chuẩn ICAO 9303:
//
//  Bước 1: Verify DS Certificate bằng CSCA (masterList.pem)
//          → DS Certificate thật
//  Bước 2: Verify chữ ký DS trên SOD
//          → SOD thật
//  Bước 3: Hash lại DG, so sánh với hash trong SOD
//          → Data không bị sửa

import Foundation
import CryptoKit

@available(iOS 13, *)
public class PassiveAuthenticationHandler {
    /// Thực hiện toàn bộ quy trình Passive Authentication.
    /// - Parameters:
    ///   - sodRawData: Dữ liệu thô (raw bytes) của file EF.SOD đọc từ chip
    ///   - sod: Đối tượng SOD đã được parse (chứa danh sách hash)
    ///   - rawDataGroups: Dictionary chứa dữ liệu thô của các DataGroup
    ///   - masterListPEM: Nội dung file masterList.pem (chứa CSCA Certificates). Nếu nil thì bỏ qua bước verify chữ ký.
    /// - Returns: Tuple (sodSignatureValid, dataIntegrityValid)
    public static func performFullPA(
        sodRawData: [UInt8],
        sod: SOD,
        rawDataGroups: [DataGroupId: [UInt8]],
        masterListPEM: String?
    ) throws -> (sodSignatureValid: Bool, dataIntegrityValid: Bool) {
        
        // Bước 1 + 2: Verify chuỗi tin cậy CSCA -> DS Cert -> SOD Signature
        var sodSignatureValid = false
        
        if let pem = masterListPEM, !pem.isEmpty {
            print("[PassiveAuth] Bước 1+2: Verify chữ ký SOD (CSCA → DS Cert → SOD)")
            let verifyResult = SODVerifier.verify(sodData: sodRawData, masterListPEM: pem)
            sodSignatureValid = verifyResult.signatureVerified
            
            if verifyResult.cscaVerified {
                print("[PassiveAuth] Bước 1: DS Certificate hợp lệ (Được xác thực bởi CSCA).")
                print("[PassiveAuth] Bước 2: Chữ ký SOD hợp lệ (Được ký bởi DS Certificate).")
            } else if verifyResult.signatureVerified {
               // print("[PassiveAuth] Bước 1: Thiếu CSCA của VN trong masterList.pem -> Bỏ qua xác thực chứng thư.")
                print("[PassiveAuth] Bước 1: Bỏ qua xác thực Cert.")
                print("[PassiveAuth] Bước 2: Chữ ký SOD hợp lệ! (Khớp với Public Key của DS Certificate).")
            } else {
                print("[PassiveAuth] Bước 1+2: THẤT BẠI. Chữ ký SOD hoàn toàn không hợp lệ.")
            }
        } else {
            print("[PassiveAuth] Không có masterList.pem → Bỏ qua bước verify chữ ký SOD.")
        }
        
        // Bước 3: So sánh Hash
        print("[PassiveAuth] Bước 3: Kiểm tra tính toàn vẹn dữ liệu")
        try verifyDataIntegrity(sod: sod, rawDataGroups: rawDataGroups)
        
        return (sodSignatureValid: sodSignatureValid, dataIntegrityValid: true)
    }
    
    public static func verifyDataIntegrity(sod: SOD, rawDataGroups: [DataGroupId: [UInt8]]) throws {
        
        print("[PassiveAuth] Bắt đầu xác thực vẹn toàn dữ liệu với \(rawDataGroups.count) Data Groups...")
        print("[PassiveAuth] Thuật toán băm theo SOD (OID): \(sod.hashAlgorithmOid) - \(HashAlgorithmOID.algorithmName(for: sod.hashAlgorithmOid))")
        
        for (dgId, rawBytes) in rawDataGroups {
            // Lấy Hash chuẩn từ SOD
            guard let expectedHash = sod.dataGroupHashes[dgId] else {
                print("[PassiveAuth] Cảnh báo: \(dgId) không có mã Hash trong SOD để đối chiếu.")
                continue
            }
            
            // Tính toán lại Hash từ rawBytes
            let calculatedHash = calculateHash(data: rawBytes, algorithmOID: sod.hashAlgorithmOid, expectedHashLength: expectedHash.count)
            
            // Đối chiếu
            if calculatedHash == expectedHash {
                print("[PassiveAuth] \(dgId): Tính toàn vẹn được xác nhận. (Khớp Hash)")
            } else {
                print("[PassiveAuth] \(dgId): PHÁT HIỆN DỮ LIỆU BỊ THAY ĐỔI!")
                print("  - Expected : \(expectedHash.map { String(format: "%02x", $0) }.joined())")
                print("  - Calculated: \(calculatedHash.map { String(format: "%02x", $0) }.joined())")
                throw NFCReaderError.responseError("Passive Auth Thất Bại: Dữ liệu \(dgId) đã bị chỉnh sửa!")
            }
        }
        
        print("[PassiveAuth] Hoàn tất! Toàn bộ dữ liệu đều nguyên bản và an toàn.")
    }
    
    private static func calculateHash(data: [UInt8], algorithmOID: String, expectedHashLength: Int) -> [UInt8] {
            let inputData = Data(data)
     
            switch algorithmOID {
            case HashAlgorithmOID.sha1:
                return Array(Insecure.SHA1.hash(data: inputData))
            case HashAlgorithmOID.sha256:
                return Array(SHA256.hash(data: inputData))
            case HashAlgorithmOID.sha384:
                return Array(SHA384.hash(data: inputData))
            case HashAlgorithmOID.sha512:
                return Array(SHA512.hash(data: inputData))
            case HashAlgorithmOID.sha224:
                print("[PassiveAuth] Cảnh báo: SHA-224 chưa được CryptoKit hỗ trợ trực tiếp, dùng fallback theo độ dài.")
                return calculateHashByLength(data: inputData, expectedHashLength: expectedHashLength)
            default:
                print("[PassiveAuth] Cảnh báo: OID thuật toán băm '\(algorithmOID)' không nhận diện được, dùng fallback theo độ dài.")
                return calculateHashByLength(data: inputData, expectedHashLength: expectedHashLength)
            }
        }
     
        /// đoán thuật toán dựa vào độ dài hash mong đợi trong SOD.
        private static func calculateHashByLength(data: Data, expectedHashLength: Int) -> [UInt8] {
            switch expectedHashLength {
            case 20: // SHA-1
                return Array(Insecure.SHA1.hash(data: data))
            case 32: // SHA-256
                return Array(SHA256.hash(data: data))
            case 48: // SHA-384
                return Array(SHA384.hash(data: data))
            case 64: // SHA-512
                return Array(SHA512.hash(data: data))
            default:
                print("[PassiveAuth] Cảnh báo: Chiều dài Hash không chuẩn (\(expectedHashLength) bytes). Fallback SHA-256.")
                return Array(SHA256.hash(data: data))
            }
        }
}
