import Foundation
import CryptoKit

final class SessionKeyGenerator {
    func deriveKey(keySeed: [UInt8], mode: KeyMode, cipherAlgName: SymmetricCipherAlgorithm = .des3) throws -> [UInt8] {
        let modeBytes: [UInt8] = [0x00, 0x00, 0x00, mode.rawValue]
        let input = keySeed + modeBytes
 
        let hash: [UInt8] = cipherAlgName.usesSHA256
            ? Array(SHA256.hash(data: input))
            : Array(Insecure.SHA1.hash(data: input))
 
        guard hash.count >= cipherAlgName.hashBytesNeeded else {
            throw SessionKeyGeneratorError.hashTooShort
        }
 
        switch cipherAlgName {
        case .des3:
            // Ka = hash[0..8), Kb = hash[8..16) -> khoá 3-key 3DES = Ka - Kb - Ka (24 bytes)
            let ka = Array(hash[0..<8])
            let kb = Array(hash[8..<16])
            return adjustDESParity(ka + kb + ka)
 
        case .aes128, .aes192, .aes256:
            return Array(hash[0..<cipherAlgName.hashBytesNeeded])
        }
        
//        let modeBytes: [UInt8] = [0x00, 0x00, 0x00, mode.rawValue]
//        
//        var sha1 = Insecure.SHA1()
//        sha1.update(data: keySeed)
//        sha1.update(data: modeBytes)
//        let hash = Array(sha1.finalize())
//        
//        let key = Array(hash[0..<16]) + Array(hash[0..<8])
//        
//        return key
    }
    
    // Chuẩn DES yêu cầu mỗi byte khoá có parity lẻ ở bit thấp nhất.
    private func adjustDESParity(_ key: [UInt8]) -> [UInt8] {
       key.map { byte in
           let base = byte & 0xFE // xoá bit thấp nhất (parity bit hiện tại)
           let onesCount = (1...7).reduce(0) { count, i in
               count + Int((base >> i) & 0x01)
           }
           // Nếu số bit 1 (trừ bit parity) đang chẵn -> set parity bit = 1 để tổng thành lẻ.
           // Nếu đang lẻ -> giữ parity bit = 0.
           return onesCount % 2 == 0 ? (base | 0x01) : base
       }
    }
}
