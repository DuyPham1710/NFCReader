public enum HashAlgorithmOID {
    static let sha1 = "1.3.14.3.2.26"
    static let sha224 = "2.16.840.1.101.3.4.2.4"
    static let sha256 = "2.16.840.1.101.3.4.2.1"
    static let sha384 = "2.16.840.1.101.3.4.2.2"
    static let sha512 = "2.16.840.1.101.3.4.2.3"
    
    static func algorithmName(for oid: String) -> String {
        switch oid {
        case HashAlgorithmOID.sha1: return "SHA-1"
        case HashAlgorithmOID.sha224: return "SHA-224"
        case HashAlgorithmOID.sha256: return "SHA-256"
        case HashAlgorithmOID.sha384: return "SHA-384"
        case HashAlgorithmOID.sha512: return "SHA-512"
        default: return "Không xác định"
        }
    }
}
