// Public key thật của chip, dùng để thực hiện ECDH (Elliptic Curve Diffie-Hellman) trong Chip Authentication.
public struct ChipAuthenticationPublicKeyInfo {
    /// OID xác định loại key: id-PK-DH ("...2.1.1") hoặc id-PK-ECDH ("...2.1.2").
    public let protocolOID: String
    /// OID thuật toán bên trong SubjectPublicKeyInfo (thường trùng hoặc liên quan protocolOID).
    public let algorithmOID: String
    /// Nội dung thật của public key (DH: số nguyên lớn dạng byte; ECDH: điểm trên đường cong).
    public let publicKeyBytes: [UInt8]
    /// Toàn bộ cấu trúc ASN.1 của subjectPublicKeyInfoBytes (để truyền cho OpenSSL)
    public let subjectPublicKeyInfoBytes: [UInt8]
    public let keyId: Int?
}
