import Foundation
import CommonCrypto
import CryptoKit

func MAC(algoName: EncryptAlgorithm, key: [UInt8], msg: [UInt8]) -> [UInt8] {
    if algoName == .DES {
        return desRetailMAC(key: key, msg: msg)
    } else {
        return aesCMAC(key: key, message: msg)
    }
}

func calcSHA1Hash(_ data: [UInt8]) -> [UInt8] {
    var sha1 = Insecure.SHA1()
    sha1.update(data: data)
    let hash = sha1.finalize()
    return Array(hash)
}

// Show log - Hex String
func binToHexRep(_ data: [UInt8]) -> String {
    return data.map { String(format: "%02X", $0) }.joined()
}

// sinh số ngẫu nhiên
func generateRandomBytes(_ count: Int) -> [UInt8] {
    // Tạo mảng rỗng
    var bytes = [UInt8](repeating: 0, count: count)
    
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    guard status == errSecSuccess else {
        return (0..<count).map { _ in UInt8(arc4random_uniform(256)) }
    }
    return bytes
}


func pad(_ data: [UInt8], blockSize: Int) -> [UInt8] {
    var res = data + [0x80]
    
    while res.count % blockSize != 0 {
        res.append(0x00)
    }
    return res
}


public func unpad( _ tounpad : [UInt8]) -> [UInt8] {
    var i = tounpad.count - 1
    while tounpad[i] == 0x00 {
        i -= 1
    }
    
    if tounpad[i] == 0x80 {
        return [UInt8](tounpad[0..<i])
    } else {
        // no padding
        return tounpad
    }
}


func xor(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
    var result = [UInt8]()
    for i in 0..<a.count {
        result.append(a[i] ^ b[i])
    }
    return result
}

func toAsn1Length(_ length: Int) -> [UInt8] {
    if length < 128 {
        return [UInt8(length)]
    }
    let bytes = inToBin(length)
    return [UInt8(0x80 | bytes.count)] + bytes
}

// giải mã độ dài của một gói dữ liệu được mã hóa theo chuẩn ASN.1
func asn1Length(_ data: [UInt8]) throws -> (length: Int, offset: Int) {
   if data.isEmpty { return (0, 0) }
    
   let first = data[0]
   if first < 128 {
       return (Int(first), 1)
   } else {
       let numBytes = Int(first & 0x7F)
       guard data.count >= numBytes + 1 else {
           throw NFCReaderError.responseError("Lỗi phân tích ASN.1 Length")
       }
       
       var len = 0
       for i in 1...numBytes {
           len = (len << 8) + Int(data[i])
       }
       return (len, numBytes + 1)
   }
}

// chuyển số nguyên thành mảng byte (vd: 256 -> [0x01, 0x00])
func inToBin(_ value: Int) -> [UInt8] {
    var v = value
    var bytes: [UInt8] = []
    
    while v > 0 {
        bytes.insert(UInt8(v & 0xFF), at: 0)    // lấy ra byte cuối cùng
        v >>= 8                                 // dịch 8 bit để bỏ byte cuối cùng ra ngoài
    }
    
    return bytes.isEmpty ? [0] : bytes
}

// Đóng gói data thành dạng TLV
func wrapDO(b: UInt8, arr: [UInt8]) -> [UInt8] {
    return [b] + toAsn1Length(arr.count) + arr
}

// Chuyển chuỗi OID (vd: "0.4.0.127.0.7.2.2.3.1.2") thành mảng bytes ASN.1
func oidToBytes(oid: String, replaceTag: Bool = false) -> [UInt8] {
    let parts = oid.split(separator: ".").compactMap { Int($0) }
    guard parts.count >= 2 else { return [] }
    
    var bytes: [UInt8] = []
    
    // 2 giá trị đầu gộp thành 1 byte: (40 * val1) + val2
    let firstByte = UInt8(40 * parts[0] + parts[1])
    bytes.append(firstByte)
    
    // Các giá trị tiếp theo encode kiểu Base 128
    for value in parts.dropFirst(2) {
        var v = value
        var encodedParts: [UInt8] = []
        if v == 0 {
            encodedParts.append(0x00)
        } else {
            while v > 0 {
                let lower7Bits = UInt8(v & 0x7F)
                encodedParts.insert(lower7Bits, at: 0)
                v >>= 7
            }
            // Đặt cờ 0x80 cho tất cả trừ byte cuối cùng
            for i in 0..<(encodedParts.count - 1) {
                encodedParts[i] |= 0x80
            }
        }
        bytes.append(contentsOf: encodedParts)
    }
    
    let tag: UInt8 = replaceTag ? 0x80 : 0x06
    return [tag] + toAsn1Length(bytes.count) + bytes
}
