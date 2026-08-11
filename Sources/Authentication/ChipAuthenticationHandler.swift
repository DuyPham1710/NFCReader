import Foundation
import OpenSSL

@available(iOS 13, macOS 10.15, *)
public class ChipAuthenticationHandler {
    private let dg14: DG14
    private let transceiver: APDUTransceiver
    private let COMMAND_CHAINING_CHUNK_SIZE = 224
    
    public var isSupported: Bool {
        return !dg14.publicKeys.isEmpty
    }
    
    public init(dg14: DG14, transceiver: APDUTransceiver) {
        self.dg14 = dg14
        self.transceiver = transceiver
    }
    
    public func doChipAuthentication() async throws {
        guard isSupported else {
            throw NFCReaderError.responseError("Chip Authentication không được hỗ trợ (không có public key trong DG14)")
        }
        
        var success = false
        for pubKeyInfo in dg14.publicKeys {
            do {
                success = try await performCA(with: pubKeyInfo)
                if success { break }
            } catch {
                print("[CA] Lỗi CA với public key \(pubKeyInfo.protocolOID): \(error)")
            }
        }
        
        if !success {
            throw NFCReaderError.responseError("Chip Authentication thất bại (không có public key nào hợp lệ)")
        }
    }
    
    private func performCA(with pubKeyInfo: ChipAuthenticationPublicKeyInfo) async throws -> Bool {
        // Tìm OID thuật toán và KeyID
        let keyId = pubKeyInfo.keyId
        let caInfo = dg14.chipAuthInfos.first { $0.keyId == keyId }
        
        // Nếu không có ChipAuthInfo, đoán dựa vào protocolOID của public key
        let finalOID = caInfo?.protocolOID ?? inferOID(from: pubKeyInfo.protocolOID)
        guard let oid = finalOID else {
            print("[CA] Bỏ qua: Không tìm thấy hoặc không thể suy diễn OID CA hợp lệ.")
            return false
        }
        
        // Hiện tại chỉ hỗ trợ ECDH
        guard pubKeyInfo.protocolOID == CAOIDHelper.idPKECDH else {
            print("[CA] Bỏ qua: SDK hiện chỉ hỗ trợ ECDH (P256), không hỗ trợ \(pubKeyInfo.protocolOID)")
            return false
        }
        
        print("[CA] Bắt đầu CA với thuật toán OID: \(oid), KeyID: \(keyId?.description ?? "nil")")
        
        // Parse Public Key chip bằng OpenSSL
        var chipPubKeyPkey: OpaquePointer? = nil
        let _ = pubKeyInfo.subjectPublicKeyInfoBytes.withUnsafeBytes { ptr in
            var newPtr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            chipPubKeyPkey = d2i_PUBKEY(nil, &newPtr, pubKeyInfo.subjectPublicKeyInfoBytes.count)
            
            if let chipPubKey = chipPubKeyPkey {
                let ecKey = EVP_PKEY_get1_EC_KEY(chipPubKey)
                let group = EC_KEY_get0_group(ecKey)
                let curveNID = EC_GROUP_get_curve_name(group)
                let curveName = OBJ_nid2sn(curveNID)
                print("[CA] Đường cong ECC thật của chip: \(String(cString: curveName!))")
                EC_KEY_free(ecKey)
            }
        }
        
        guard let chipPubKey = chipPubKeyPkey else {
            print("[CA] Không thể parse Chip Public Key bằng OpenSSL.")
            return false
        }
        defer { EVP_PKEY_free(chipPubKey) }
        
        // Generate Ephemeral Keypair from parameters from DG14 Public key
        var ephemeralKeyPair: OpaquePointer? = nil
        let pctx = EVP_PKEY_CTX_new(chipPubKey, nil)
        EVP_PKEY_keygen_init(pctx)
        EVP_PKEY_keygen(pctx, &ephemeralKeyPair)
        EVP_PKEY_CTX_free(pctx)
        
        guard let ephemeralKey = ephemeralKeyPair else {
            print("[CA] Không thể sinh khoá ECDH (ephemeral key).")
            return false
        }
        defer { EVP_PKEY_free(ephemeralKey) }
        
        guard let publicKeyData = OpenSSLUtils.getPublicKeyData(from: ephemeralKey) else {
            print("[CA] Không thể lấy mảng byte của ephemeral public key.")
            return false
        }
        
        // Gửi MSE:Set AT (báo chip sắp làm CA, dùng thuật toán OID này, với keyID này)
        let mseResponse = try await transceiver.sendMSESetATIntAuth(oid: oid, keyId: keyId)
        guard mseResponse.isSuccess else {
            print("[CA] MSE:Set AT thất bại: SW=\(mseResponse.statusWordHex)")
            return false
        }
        
        // Gửi General Authenticate (Gửi public key của điện thoại sang chip)
        let pubKeyBytes = [UInt8](publicKeyData)
        let do80 = wrapDO(b: 0x80, arr: pubKeyBytes) // Đóng gói vào Ephemeral Public Key DO (0x80)
        
        // Cắt nhỏ dữ liệu nếu quá dài
        let chunks = stride(from: 0, to: do80.count, by: COMMAND_CHAINING_CHUNK_SIZE).map {
            Array(do80[$0 ..< min($0 + COMMAND_CHAINING_CHUNK_SIZE, do80.count)])
        }
        
        var gaResponse: APDUResponse?
        for (index, chunk) in chunks.enumerated() {
            let isLast = (index == chunks.count - 1)
            gaResponse = try await transceiver.sendGeneralAuthenticate(data: chunk, isLast: isLast)
            if gaResponse?.isSuccess == false {
                print("[CA] General Authenticate thất bại tại chunk \(index): SW=\(gaResponse!.statusWordHex)")
                return false
            }
        }
        
        // Tính Shared Secret
        let sharedSecretBytes = OpenSSLUtils.computeSharedSecret(privateKeyPair: ephemeralKey, publicKey: chipPubKey)
        guard !sharedSecretBytes.isEmpty else {
            print("[CA] Tính Shared Secret thất bại.")
            return false
        }
        
        // Khởi động lại Secure Messaging với bộ khoá mới
        try restartSecureMessaging(oid: oid, sharedSecret: sharedSecretBytes)
        
        return true
    }
    
    private func restartSecureMessaging(oid: String, sharedSecret: [UInt8]) throws {
        // Dựa vào OID để biết chip muốn mã hoá AES hay DES cho Secure Messaging
        let cipherAlg = CAOIDHelper.getCipherAlgorithm(for: oid)
        
        let sessionGenerator = SessionKeyGenerator()
        let ksEnc = try sessionGenerator.deriveKey(keySeed: sharedSecret, mode: .ENC_MODE, cipherAlgName: cipherAlg)
        let ksMac = try sessionGenerator.deriveKey(keySeed: sharedSecret, mode: .MAC_MODE, cipherAlgName: cipherAlg)
        
        // Khởi tạo lại SSC bằng 0
        let ssc = [UInt8](repeating: 0, count: 8)
        
        let encryptAlgo: EncryptAlgorithm = (cipherAlg == .des3) ? .DES : .AES
        
        let sm = SecureMessaging(algoName: encryptAlgo, sessionEncKey: ksEnc, sessionMacKey: ksMac, ssc: ssc)
        transceiver.secureMessaging = sm
        
        print("[CA] Thành công! Secure Messaging đã được nâng cấp lên \(encryptAlgo == .AES ? "AES" : "3DES")")
    }
    
    private func inferOID(from publicKeyOID: String) -> String? {
        if publicKeyOID == CAOIDHelper.idPKECDH {
            // Nếu chip là ECDH mà không nói rõ mã hoá gì, ta đoán là AES-128 (chuẩn an toàn chung)
            print("[CA] Cảnh báo: Không có ChipAuthInfo, đoán thuật toán là idCAECDHAESCBC_CMAC128")
            return CAOIDHelper.idCAECDHAESCBC_CMAC128
        } else if publicKeyOID == CAOIDHelper.idPKDH {
            print("[CA] Cảnh báo: Không có ChipAuthInfo, đoán thuật toán là idCADH3DESCBCCBC")
            return CAOIDHelper.idCADH3DESCBCCBC
        }
        return nil
    }
}
