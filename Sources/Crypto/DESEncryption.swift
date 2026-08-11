import Foundation
import CommonCrypto

func tripleDESEncrypt(key: [UInt8], message: [UInt8], iv: [UInt8]) -> [UInt8] {
    var fixedKey = key
    if key.count == 16 {
        fixedKey += key[0..<8]  // Mở rộng 16 -> 24 bytes: K1 + K2 + K1
    }

    let dataLength = message.count
    let cryptLen = dataLength + kCCBlockSize3DES
    var cryptData = Data(count: cryptLen)
    var numBytesEncrypted = 0

    let status = fixedKey.withUnsafeBytes { keyBytes in
        message.withUnsafeBytes { dataBytes in
            iv.withUnsafeBytes { ivBytes in
                cryptData.withUnsafeMutableBytes { cryptBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithm3DES),
                        CCOptions(0),  // Không padding
                        keyBytes.baseAddress,
                        size_t(kCCKeySize3DES),
                        ivBytes.baseAddress,
                        dataBytes.baseAddress,
                        dataLength,
                        cryptBytes.bindMemory(to: UInt8.self).baseAddress,
                        cryptLen,
                        &numBytesEncrypted
                    )
                }
            }
        }
    }

    guard status == kCCSuccess else {
        print("[CryptoUtils] 3DES Encrypt Error: \(status)")
        return []
    }
    cryptData.count = Int(numBytesEncrypted)
    return [UInt8](cryptData)
}


// Giải mã bằng 3DES
func tripleDESDecrypt(key: [UInt8], message: [UInt8], iv: [UInt8]) -> [UInt8] {
    var fixedKey = key
    if key.count == 16 {
        fixedKey += key[0..<8]
    }

    let dataLength = message.count
    let cryptLen = dataLength + kCCBlockSize3DES
    var cryptData = Data(count: cryptLen)
    var numBytesDecrypted = 0

    let status = fixedKey.withUnsafeBytes { keyBytes in
        message.withUnsafeBytes { dataBytes in
            cryptData.withUnsafeMutableBytes { cryptBytes in
                CCCrypt(
                    CCOperation(kCCDecrypt),
                    CCAlgorithm(kCCAlgorithm3DES),
                    CCOptions(0),
                    keyBytes.baseAddress,
                    size_t(kCCKeySize3DES),
                    iv,
                    dataBytes.baseAddress, dataLength,
                    cryptBytes.bindMemory(to: UInt8.self).baseAddress,
                    cryptLen,
                    &numBytesDecrypted
                )
            }
        }
    }

    guard status == kCCSuccess else {
        print("[CryptoUtils] 3DES Decrypt Error: \(status)")
        return []
    }
    
    cryptData.count = Int(numBytesDecrypted)
    return [UInt8](cryptData)
}

/// Mã hóa bằng DES đơn (1 key 8 bytes)
func DESEncrypt(key: [UInt8], message: [UInt8], iv: [UInt8], options: UInt32 = 0) -> [UInt8] {
    let dataLength = message.count
    let cryptLen = dataLength + kCCBlockSizeDES
    var cryptData = Data(count: cryptLen)
    var numBytesEncrypted = 0

    let status = key.withUnsafeBytes { keyBytes in
        message.withUnsafeBytes { dataBytes in
            iv.withUnsafeBytes { ivBytes in
                cryptData.withUnsafeMutableBytes { cryptBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmDES),
                        CCOptions(options),
                        keyBytes.baseAddress,
                        size_t(kCCKeySizeDES),
                        ivBytes.baseAddress,
                        dataBytes.baseAddress,
                        dataLength,
                        cryptBytes.bindMemory(to: UInt8.self).baseAddress,
                        cryptLen,
                        &numBytesEncrypted
                    )
                }
            }
        }
    }

    guard status == kCCSuccess else { return [] }
    cryptData.count = Int(numBytesEncrypted)
    
    return [UInt8](cryptData)
}

/// Giải mã bằng DES đơn
func DESDecrypt(key: [UInt8], message: [UInt8], iv: [UInt8], options: UInt32 = 0) -> [UInt8] {
    let dataLength = message.count
    let cryptLen = dataLength + kCCBlockSizeDES
    var cryptData = Data(count: cryptLen)
    var numBytesDecrypted = 0

    let status = key.withUnsafeBytes { keyBytes in
        message.withUnsafeBytes { dataBytes in
            iv.withUnsafeBytes { ivBytes in
                cryptData.withUnsafeMutableBytes { cryptBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmDES),
                        CCOptions(options),
                        keyBytes.baseAddress,
                        size_t(kCCKeySizeDES),
                        ivBytes.baseAddress,
                        dataBytes.baseAddress,
                        dataLength,
                        cryptBytes.bindMemory(to: UInt8.self).baseAddress,
                        cryptLen,
                        &numBytesDecrypted
                    )
                }
            }
        }
    }

    guard status == kCCSuccess else { return [] }
    cryptData.count = Int(numBytesDecrypted)
    
    return [UInt8](cryptData)
}

/// Tính DES Retail MAC (dùng cho BAC và Secure Messaging 3DES).
/// Thuật toán:
///   1. Chia message thành các block 8 bytes.
///   2. Mã hóa DES đơn (key = K1 = 8 bytes đầu) lần lượt qua từng block (CBC thủ công).
///   3. Kết quả cuối cùng: DES giải mã bằng K2, rồi DES mã hóa lại bằng K1.
/// Key phải 16 bytes (K1 = key[0..<8], K2 = key[8..<16]).
func desRetailMAC(key: [UInt8], msg: [UInt8]) -> [UInt8] {
    let k1 = [UInt8](key[0..<8])
    let k2 = [UInt8](key[8..<16])
    let blockCount = msg.count / 8

    var y: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]

    for i in 0..<blockCount {
        let block = [UInt8](msg[i * 8 ..< i * 8 + 8])
        y = DESEncrypt(key: k1, message: block, iv: y)
    }

    let zeroIV: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
    let decryptWithK2 = DESDecrypt(key: k2, message: y, iv: zeroIV, options: UInt32(kCCOptionECBMode))
    let mac = DESEncrypt(key: k1, message: decryptWithK2, iv: zeroIV, options: UInt32(kCCOptionECBMode))

    return mac
}

