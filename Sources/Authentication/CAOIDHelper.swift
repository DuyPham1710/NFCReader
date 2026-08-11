//  Bảng tra cứu OID (Object Identifier) dùng trong Chip Authentication

import Foundation

struct CAOIDHelper {
    static let idCADH3DESCBCCBC = "0.4.0.127.0.7.2.2.3.1.1"
    static let idCAECDH3DESCBCCBC = "0.4.0.127.0.7.2.2.3.2.1"
    
    static let idCADHAESCBC_CMAC128 = "0.4.0.127.0.7.2.2.3.1.2"
    static let idCADHAESCBC_CMAC192 = "0.4.0.127.0.7.2.2.3.1.3"
    static let idCADHAESCBC_CMAC256 = "0.4.0.127.0.7.2.2.3.1.4"
    
    static let idCAECDHAESCBC_CMAC128 = "0.4.0.127.0.7.2.2.3.2.2"
    static let idCAECDHAESCBC_CMAC192 = "0.4.0.127.0.7.2.2.3.2.3"
    static let idCAECDHAESCBC_CMAC256 = "0.4.0.127.0.7.2.2.3.2.4"
    
    static let idPKDH = "0.4.0.127.0.7.2.2.1.1"
    static let idPKECDH = "0.4.0.127.0.7.2.2.1.2"
    
    /// Trả về thuật toán mã hoá đối xứng và độ dài khoá dựa vào OID của Chip Authentication
    static func getCipherAlgorithm(for oid: String) -> SymmetricCipherAlgorithm {
        switch oid {
        case idCADH3DESCBCCBC, idCAECDH3DESCBCCBC:
            return .des3
            
        case idCADHAESCBC_CMAC128, idCAECDHAESCBC_CMAC128:
            return .aes128
            
        case idCADHAESCBC_CMAC192, idCAECDHAESCBC_CMAC192:
            return .aes192
            
        case idCADHAESCBC_CMAC256, idCAECDHAESCBC_CMAC256:
            return .aes256
            
        default:
            print("[CAOIDHelper] OID không nhận diện được (\(oid)), fallback về AES128")
            return .aes128
        }
    }
}
