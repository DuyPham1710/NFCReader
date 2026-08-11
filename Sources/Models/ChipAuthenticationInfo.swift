/// Khai báo thuật toán Chip Authentication mà chip hỗ trợ
public struct ChipAuthenticationInfo {
    // OID xác định thuật toán cụ thể, vd "0.4.0.127.0.7.2.2.3.1.2" = id-CA-DH-AES-CBC-CMAC-128
    public let protocolOID: String
    public let version: Int
    // keyId dùng để khớp với đúng public key tương ứng trong
    // ChipAuthenticationPublicKeyInfo, nếu chip công bố nhiều key
    public let keyId: Int?
}
