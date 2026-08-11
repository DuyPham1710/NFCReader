// EF.COM chứa một danh sách các Data Group đang thực sự được lưu trên con chip
// tránh gọi SELECT FILE vào 1 DataGroup không tồn tại trên thẻ (chip sẽ trả lỗi)

import Foundation

public struct COM {
    // Phiên bản LDS (Logical Data Structure - cấu trúc dữ liệu của thẻ)
    public let ldsVersion: String
    // Phiên bản Unicode dùng để encode text, dạng chuỗi vd "040000".
    public let unicodeVersion: String
    public let dataGroupsPresent: [DataGroupId]

    // Chỉ liệt kê các DG nằm trong phạm vi SDK hỗ trợ
    private static let tagToDataGroup: [UInt8: DataGroupId] = [
        0x61: .DG1,
        0x75: .DG2,
        0x63: .DG3,
        0x76: .DG4,
        0x65: .DG5,
        0x66: .DG6,
        0x67: .DG7,
        0x68: .DG8,
        0x69: .DG9,
        0x6A: .DG10,
        0x6B: .DG11,
        0x6C: .DG12,
        0x6D: .DG13,
        0x6E: .DG14,
        0x6F: .DG15,
        0x70: .DG16
    ]

    public init(data: [UInt8]) throws {
        var offset = 0

        // Tag ngoài cùng phải là 0x60
        guard !data.isEmpty, data[offset] == 0x60 else {
            throw NFCReaderError.responseError("EF.COM: thiếu tag 0x60")
        }
        
        offset += 1

        let outerLength = try asn1Length(Array(data[offset...]))
        offset += outerLength.offset
        let contentEnd = offset + outerLength.length

        guard contentEnd <= data.count else {
            throw NFCReaderError.responseError("EF.COM: length vượt quá dữ liệu thực tế")
        }

        var ldsVersion = ""
        var unicodeVersion = ""
        var tagListBytes: [UInt8] = []

        // Duyệt qua từng TLV con bên trong (5F01, 5F36, 5C)
        while offset < contentEnd {
            let (tag, tagLength) = try Self.readTag(data, at: offset)
            offset += tagLength

            let lengthResult = try asn1Length(Array(data[offset...]))
            offset += lengthResult.offset

            guard offset + lengthResult.length <= data.count else {
                throw NFCReaderError.responseError("EF.COM: length của 1 field vượt quá dữ liệu")
            }
            
            let value = Array(data[offset..<(offset + lengthResult.length)])
            offset += lengthResult.length

            switch tag {
            case 0x5F01:
                ldsVersion = String(bytes: value, encoding: .ascii) ?? ""
            case 0x5F36:
                unicodeVersion = String(bytes: value, encoding: .ascii) ?? ""
            case 0x5C:
                tagListBytes = value
            default:
                break // tag lạ, skip
            }
        }

        self.ldsVersion = ldsVersion
        self.unicodeVersion = unicodeVersion
        self.dataGroupsPresent = tagListBytes.compactMap { Self.tagToDataGroup[$0] }
    }

    /// Đọc 1 tag ASN.1 tại vị trí offset, trả về (giá trị tag, số byte tag chiếm)
    /// Hỗ trợ cả tag 1 byte (vd 0x5C) và tag nhiều byte (vd 0x5F01 - byte đầu có
    /// 5 bit thấp đều là 1, báo hiệu còn byte tag tiếp theo).
    private static func readTag(_ data: [UInt8], at offset: Int) throws -> (tag: Int, length: Int) {
        guard offset < data.count else {
            throw NFCReaderError.responseError("EF.COM: hết dữ liệu khi đọc tag")
        }
        let firstByte = data[offset]

        // Nếu 5 bit thấp của byte đầu không phải toàn 1 (0x1F) -> tag 1 byte
        guard (firstByte & 0x1F) == 0x1F else {
            return (Int(firstByte), 1)
        }

        // Tag nhiều byte: byte đầu (vd 0x5F) + các byte sau
        guard offset + 1 < data.count else {
            throw NFCReaderError.responseError("EF.COM: tag nhiều byte bị cắt cụt")
        }
        
        let secondByte = data[offset + 1]
        let tagValue = (Int(firstByte) << 8) | Int(secondByte)
        return (tagValue, 2)
    }
}
