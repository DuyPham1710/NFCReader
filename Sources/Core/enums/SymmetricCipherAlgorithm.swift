// Thuật toán mã hoá đối xứng mà khoá sinh ra sẽ phục vụ.
// Chip trả về thuật toán này trong DG14 (cho bước CA) hoặc trong PACEInfo (cho PACE).
// BAC luôn cố định dùng `.des3`.
enum SymmetricCipherAlgorithm {
    case des3
    case aes128
    case aes192
    case aes256
 
    var usesSHA256: Bool {
        switch self {
        case .aes192, .aes256: return true
        case .des3, .aes128: return false
        }
    }
 
    // Số byte cần lấy từ hash để tạo khoá
    // 3DES lấy 16 byte rồi mở rộng thành 24 byte
    var hashBytesNeeded: Int {
        switch self {
        case .des3: return 16
        case .aes128: return 16
        case .aes192: return 24
        case .aes256: return 32
        }
    }
}
