//  Parse DG13 (EF.DG13) - Data Group đặc thù của thẻ CCCD Việt Nam (Bộ Công An).
//
//  Cấu trúc ASN.1:
//    6D L                       -- DG13 tag
//      30 L                     -- SEQUENCE
//        02 01 01               -- INTEGER version
//        06 ...                 -- OID
//        31 L                   -- SET OF records
//          30 L                 -- SEQUENCE (1 trường)
//            02 01 <fieldId>    -- INTEGER: field identifier
//            0C/13 L <value>    -- UTF8String hoặc PrintableString: giá trị
//          ...
//
//  Danh sách field ID:
//    01 = Số CCCD
//    02 = Họ tên
//    03 = Ngày sinh (DD/MM/YYYY)
//    04 = Giới tính
//    05 = Quốc tịch
//    06 = Dân tộc
//    07 = Tôn giáo
//    08 = Quê quán
//    09 = Nơi thường trú
//    0A = Đặc điểm nhận dạng
//    0B = Ngày cấp (DD/MM/YYYY)
//    0C = Ngày hết hạn (DD/MM/YYYY)
//    0D = Cha/Mẹ (SEQUENCE lồng nhau)
//    10 = Chip ID
//

import Foundation

public struct DG13 {
    public let documentNumber: String?
    public let fullName: String?
    public let dateOfBirth: String?
    public let sex: String?
    public let nationality: String?
    public let ethnicity: String?
    public let religion: String?
    public let hometown: String?
    public let permanentAddress: String?
    public let personalCharacteristics: String?
    public let dateOfIssue: String?
    public let dateOfExpiry: String?
    public let fatherName: String?
    public let motherName: String?
    public let chipId: String?
    
    public init(data: [UInt8]) throws {
        var fields: [Int: String] = [:]
        var fatherNameParsed: String? = nil
        var motherNameParsed: String? = nil
        
        // Đọc root node 0x6D
        let root = try ASN1Node.parse(data)
        guard root.tag == 0x6D, let outerSeq = root.children.first, outerSeq.tag == 0x30 else {
            throw NFCReaderError.responseError("DG13: Cấu trúc ngoài không hợp lệ")
        }
        
        // Tìm SET OF (tag 0x31) bên trong SEQUENCE
        guard let recordSet = outerSeq.children.first(where: { $0.tag == 0x31 }) else {
            throw NFCReaderError.responseError("DG13: Không tìm thấy SET OF records")
        }
        
        // Duyệt qua từng SEQUENCE con trong SET
        for record in recordSet.children where record.tag == 0x30 {
            guard record.children.count >= 2 else { continue }
            
            // Lấy Field ID từ INTEGER đầu tiên
            let idNode = record.children[0]
            guard idNode.tag == 0x02, let fieldId = DG13.readInt(from: idNode.rawValue) else { continue }
            
            let valueNode = record.children[1]
            
            if fieldId == 0x0D {
                func extractName(from seq: ASN1Node) -> String? {
                    guard seq.tag == 0x30,
                          let nameNode = seq.children.first(where: { $0.tag == 0x0C || $0.tag == 0x13 }),
                          let str = String(bytes: nameNode.rawValue, encoding: .utf8),
                          !str.isEmpty
                    else { return nil }
                    return str
                }
                if record.children.count >= 2 {
                    fatherNameParsed = extractName(from: record.children[1])
                }
                if record.children.count >= 3 {
                    motherNameParsed = extractName(from: record.children[2])
                }
                print("[DG13] Field 0x0D: Cha: \(fatherNameParsed ?? ""), Mẹ: \(motherNameParsed ?? "")")
            } else if valueNode.tag == 0x0C || valueNode.tag == 0x13 {
                // UTF8String hoặc PrintableString - decode thành String
                if let str = String(bytes: valueNode.rawValue, encoding: .utf8) {
                    fields[fieldId] = str
                    print(String(format: "[DG13] Field 0x%02X: %@", fieldId, str))
                                    } else {
                                        print(String(format: "[DG13] Field 0x%02X: (Rỗng)", fieldId))
                                    }
            }
        }
        
        documentNumber = fields[0x01]
        fullName = fields[0x02]
        dateOfBirth = fields[0x03]
        sex = fields[0x04]
        nationality = fields[0x05]
        ethnicity = fields[0x06]
        religion = fields[0x07]
        hometown = fields[0x08]
        permanentAddress = fields[0x09]
        personalCharacteristics = fields[0x0A]
        dateOfIssue = fields[0x0B]
        dateOfExpiry = fields[0x0C]
        fatherName = fatherNameParsed
        motherName = motherNameParsed
        chipId = fields[0x10]
    }
    
    // Đọc giá trị INTEGER nhỏ từ mảng bytes
    private static func readInt(from bytes: [UInt8]) -> Int? {
        guard !bytes.isEmpty else { return nil }
        var value = 0
        for byte in bytes {
            value = (value << 8) | Int(byte)
        }
        return value
    }
}
