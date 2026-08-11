import Foundation
import CommonCrypto

func AESECBEncrypt(key: [UInt8], message: [UInt8]) -> [UInt8] {
    let dataLength = message.count
    let cryptLen = message.count + kCCBlockSizeAES128
    var cryptData = Data(count: cryptLen)
    
    let keyLength = size_t(key.count)
    let operation = CCOperation(kCCEncrypt)
    let algorithm = CCAlgorithm(kCCAlgorithmAES)
    let options = CCOptions(kCCOptionECBMode)
    
    var numBytesEncrypted = 0
    let cryptStatus = key.withUnsafeBytes { keyBytes in
        message.withUnsafeBytes { dataBytes in
            cryptData.withUnsafeMutableBytes { cryptBytes in
                CCCrypt(operation, algorithm, options,
                        keyBytes.baseAddress, keyLength,
                        nil,
                        dataBytes.baseAddress, dataLength,
                        cryptBytes.bindMemory(to: UInt8.self).baseAddress, cryptLen,
                        &numBytesEncrypted)
            }
        }
    }
    
    if cryptStatus == kCCSuccess {
        cryptData.count = Int(numBytesEncrypted)
        return [UInt8](cryptData)
    } else {
        print("AES ECB Encrypt Error: \(cryptStatus)")
    }
    return []
}


func AESEncrypt(key: [UInt8], message: [UInt8], iv: [UInt8]) -> [UInt8] {
    let dataLength = message.count
    let cryptLen = message.count + kCCBlockSizeAES128
    var cryptData = Data(count: cryptLen)
    
    let keyLength = size_t(key.count)
    let operation = CCOperation(kCCEncrypt)
    let algorithm = CCAlgorithm(kCCAlgorithmAES)
    let options = CCOptions(0)
    
    var numBytesEncrypted = 0
    let cryptStatus = key.withUnsafeBytes { keyBytes in
        message.withUnsafeBytes { dataBytes in
            iv.withUnsafeBytes { ivBytes in
                cryptData.withUnsafeMutableBytes { cryptBytes in
                    CCCrypt(operation, algorithm, options,
                            keyBytes.baseAddress, keyLength,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress, dataLength,
                            cryptBytes.bindMemory(to: UInt8.self).baseAddress, cryptLen,
                            &numBytesEncrypted)
                }
            }
        }
    }
    
    if cryptStatus == kCCSuccess {
        cryptData.count = Int(numBytesEncrypted)
        return [UInt8](cryptData)
    } else {
        print("AES Encrypt Error: \(cryptStatus)")
    }
    return []
}


func AESDecrypt(key: [UInt8], message: [UInt8], iv: [UInt8]) -> [UInt8] {
    let dataLength = message.count
    let cryptLen = message.count + kCCBlockSizeAES128
    var cryptData = Data(count: cryptLen)
    
    let keyLength = size_t(key.count)
    let operation = CCOperation(kCCDecrypt)
    let algorithm = CCAlgorithm(kCCAlgorithmAES)
    let options = CCOptions(0)
    
    var numBytesEncrypted = 0
    let cryptStatus = key.withUnsafeBytes { keyBytes in
        message.withUnsafeBytes { dataBytes in
            iv.withUnsafeBytes { ivBytes in
                cryptData.withUnsafeMutableBytes { cryptBytes in
                    CCCrypt(operation, algorithm, options,
                            keyBytes.baseAddress, keyLength,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress, dataLength,
                            cryptBytes.bindMemory(to: UInt8.self).baseAddress, cryptLen,
                            &numBytesEncrypted)
                }
            }
        }
    }
    
    if cryptStatus == kCCSuccess {
        cryptData.count = Int(numBytesEncrypted)
        return [UInt8](cryptData)
    } else {
        print("AES Decrypt Error: \(cryptStatus)")
    }
    return []
}

func aesCMAC(key: [UInt8], message: [UInt8]) -> [UInt8] {
    // Generate Subkeys K1, K2
    let zeroBlock = [UInt8](repeating: 0, count: 16)
    let L = AESECBEncrypt(key: key, message: zeroBlock)
    
    func shiftLeftAndXor(_ block: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 16)
        var carry: UInt8 = 0
        for i in (0..<16).reversed() {
            result[i] = (block[i] << 1) | carry
            carry = (block[i] & 0x80) != 0 ? 1 : 0
        }
        if carry == 1 {
            result[15] ^= 0x87
        }
        return result
    }
    
    let K1 = shiftLeftAndXor(L)     // K1 dùng khi block cuối cùng đầy đủ 16 byte
    let K2 = shiftLeftAndXor(K1)    // K2 dùng khi block cuối cùng bị thiếu (phải pad thêm)
    
    // Xác định block cuối cùng
    let n = (message.count + 15) / 16   // số block cần dùng
    let isCompleteBlock = (n != 0) && (message.count % 16 == 0)
    
    var lastBlock = [UInt8]()
    if isCompleteBlock {
        let start = (n - 1) * 16
        lastBlock = Array(message[start..<start+16])
        lastBlock = xor(lastBlock, K1)
    } else {
        let paddingLength = 16 - (message.count % 16)
        var padded = Array(message.suffix(message.count % 16))
        padded.append(0x80)
        padded.append(contentsOf: [UInt8](repeating: 0, count: paddingLength - 1))
        lastBlock = xor(padded, K2)
    }
    
    // CBC MAC Processing
    var X = [UInt8](repeating: 0, count: 16)
    let blocks = max(1, n)
    
    for i in 0..<(blocks - 1) {
        let block = Array(message[(i * 16)..<(i * 16 + 16)])
        let Y = xor(X, block)
        X = AESECBEncrypt(key: key, message: Y)
    }
    
    let Y = xor(X, lastBlock)
    let T = AESECBEncrypt(key: key, message: Y)
    
    return T
}
