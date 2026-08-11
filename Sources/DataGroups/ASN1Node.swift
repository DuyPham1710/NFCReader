//  Bộ parser ASN.1 BER/DER tối giản, dùng chung cho các cấu trúc lồng nhau
//  phức tạp hơn COM (vd DG14 chứa SET OF SecurityInfo, mỗi SecurityInfo lại là 1 SEQUENCE chứa OID + SubjectPublicKeyInfo...)
//
//  Không cố parse đầy đủ mọi kiểu ASN.1 (không cần thiết cho phạm vi CCCD),
//  chỉ đủ để đọc: SEQUENCE (0x30), SET (0x31), OBJECT IDENTIFIER (0x06),
//  INTEGER (0x02), BIT STRING (0x03), OCTET STRING (0x04).
//

import Foundation

/// 1 node trong cây ASN.1 - có thể là node "constructed" (chứa children, vd SEQUENCE/SET)
/// hoặc "primitive" (chứa bytes thô, vd INTEGER/OID/BIT STRING).
struct ASN1Node {
    let tag: UInt8
    let isConstructed: Bool
    /// Bytes thô của phần "value"
    let rawValue: [UInt8]
    /// Toàn bộ bytes của node này (bao gồm cả tag, length và value)
    let fullBytes: [UInt8]
    /// Chỉ có giá trị nếu `isConstructed == true`
    let children: [ASN1Node]

    /// Parse toàn bộ 1 mảng byte thành 1 ASN1Node gốc (giả định chỉ có đúng 1 node ở top-level).
    static func parse(_ data: [UInt8]) throws -> ASN1Node {
        var offset = 0
        return try parseNode(data, offset: &offset)
    }

    /// Parse tất cả các node liên tiếp trong 1 mảng byte (dùng khi biết trước
    /// đây là 1 chuỗi nhiều TLV nối tiếp, vd nội dung bên trong 1 SET/SEQUENCE).
    static func parseAll(_ data: [UInt8]) throws -> [ASN1Node] {
        var nodes: [ASN1Node] = []
        var offset = 0
        while offset < data.count {
            nodes.append(try parseNode(data, offset: &offset))
        }
        return nodes
    }

    private static func parseNode(_ data: [UInt8], offset: inout Int) throws -> ASN1Node {
        let startOffset = offset
        guard offset < data.count else {
            throw NFCReaderError.responseError("ASN1: hết dữ liệu khi đọc tag")
        }
        let firstTagByte = data[offset]
        offset += 1

        // Tag nhiều byte (5 bit thấp của byte đầu = 0x1F) - đọc thêm các byte tag tiếp theo
        if (firstTagByte & 0x1F) == 0x1F {
            while offset < data.count, (data[offset] & 0x80) != 0 {
                offset += 1
            }
            offset += 1 // byte cuối cùng của tag nhiều byte (bit cao = 0)
        }

        let isConstructed = (firstTagByte & 0x20) != 0

        let lengthResult = try asn1Length(Array(data[offset...]))
        offset += lengthResult.offset

        guard offset + lengthResult.length <= data.count else {
            throw NFCReaderError.responseError("ASN1: length vượt quá dữ liệu thực tế")
        }
        
        let value = Array(data[offset..<(offset + lengthResult.length)])
        offset += lengthResult.length

        let children = isConstructed ? try parseAll(value) : []
        let fullNodeBytes = Array(data[startOffset..<offset])
        return ASN1Node(tag: firstTagByte, isConstructed: isConstructed, rawValue: value, fullBytes: fullNodeBytes, children: children)
    }

    /// Decode OID (tag 0x06) từ bytes thô sang dạng chuỗi "0.4.0.127.0.7.2.2.1.1".
    var oidString: String? {
        guard tag == 0x06, !rawValue.isEmpty else { return nil }
        var arcs: [Int] = []
        let first = Int(rawValue[0])
        arcs.append(first / 40)
        arcs.append(first % 40)

        var value = 0
        for byte in rawValue.dropFirst() {
            value = (value << 7) | Int(byte & 0x7F)
            if (byte & 0x80) == 0 {
                arcs.append(value)
                value = 0
            }
        }
        return arcs.map(String.init).joined(separator: ".")
    }

    /// Decode INTEGER (tag 0x02) sang Int - chỉ dùng cho số nhỏ (vd version, keyId).
    var intValue: Int? {
        guard tag == 0x02, !rawValue.isEmpty else { return nil }
        var result = 0
        for byte in rawValue {
            result = (result << 8) | Int(byte)
        }
        return result
    }

    /// Nội dung thật của BIT STRING (tag 0x03) - byte đầu là "số bit đệm thừa", bỏ qua.
    var bitStringContent: [UInt8]? {
        guard tag == 0x03, !rawValue.isEmpty else { return nil }
        return Array(rawValue.dropFirst())
    }
}
