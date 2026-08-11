//  Đại diện cho 3 thông tin MRZ cần thiết để
//  mở kênh truy cập bảo mật (BAC/PACE) với chip trên thẻ CCCD/hộ chiếu,
//  theo chuẩn ICAO Doc 9303:
//    - Document Number  (Số CCCD/hộ chiếu)
//    - Date of Birth    (Ngày sinh, YYMMDD)
//    - Date of Expiry   (Ngày hết hạn thẻ, YYMMDD)
//
//  MRZKey chịu trách nhiệm:
//    1. Validate định dạng đầu vào.
//    2. Check digit theo thuật toán ICAO 9303 (trọng số 7-3-1).
//    3. Sinh ra mrzKey dùng làm seed để BACHandler
//       derive ra Kenc/Kmac (khoá mã hoá & khoá MAC cho Secure Messaging).
//

import Foundation

public struct MRZKey: @unchecked Sendable {

    /// Số CCCD
    public let documentNumber: String

    /// Ngày sinh, định dạng YYMMDD (vd: 990101 = 01/01/1999)
    public let dateOfBirth: String

    /// Ngày hết hạn thẻ, định dạng YYMMDD
    public let dateOfExpiry: String

    public init(documentNumber: String, dateOfBirth: String, dateOfExpiry: String) throws {
        let docNumber = documentNumber.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()

        guard !docNumber.isEmpty, docNumber.count <= 12 else {
            throw NFCReaderError.invalidMRZKey
        }
        guard MRZKey.isValidDateString(dateOfBirth) else {
            throw NFCReaderError.invalidMRZKey
        }
        guard MRZKey.isValidDateString(dateOfExpiry) else {
            throw NFCReaderError.invalidMRZKey
        }

        self.documentNumber = docNumber
        self.dateOfBirth = dateOfBirth
        self.dateOfExpiry = dateOfExpiry
    }
    
    public init(mrzKey: String) throws {
        let cleanMRZ = mrzKey.replacingOccurrences(of: "\n", with: "")
                             .replacingOccurrences(of: "\r", with: "")
                             .trimmingCharacters(in: .whitespacesAndNewlines)
                             .uppercased()
        
        let chars = Array(cleanMRZ)
        var rawDocNum, docCd, rawDob, dobCd, rawDoe, doeCd: String
        
        if chars.count == 24 {
            // 24 ký tự (Đã được trích xuất sẵn)
            rawDocNum = String(chars[0...8])
            docCd = String(chars[9])
            rawDob = String(chars[10...15])
            dobCd = String(chars[16])
            rawDoe = String(chars[17...22])
            doeCd = String(chars[23])
        } else if chars.count == 90 {
            // Chuẩn TD1 (CCCD Việt Nam - 3 dòng x 30 ký tự)
            rawDocNum = String(chars[5...13])
            docCd = String(chars[14])
            rawDob = String(chars[30...35])
            dobCd = String(chars[36])
            rawDoe = String(chars[38...43])
            doeCd = String(chars[44])
        } else if chars.count == 88 {
            // Chuẩn TD3 (Hộ chiếu - 2 dòng x 44 ký tự)
            rawDocNum = String(chars[44...52])
            docCd = String(chars[53])
            rawDob = String(chars[57...62])
            dobCd = String(chars[63])
            rawDoe = String(chars[65...70])
            doeCd = String(chars[71])
        } else {
            throw NFCReaderError.invalidMRZKey
        }
        
        // Verify Check Digit chống quét sai (OCR Error)
        guard String(MRZKey.checkDigit(for: rawDocNum)) == docCd,
              String(MRZKey.checkDigit(for: rawDob)) == dobCd,
              String(MRZKey.checkDigit(for: rawDoe)) == doeCd else {
            throw NFCReaderError.invalidMRZKey
        }
        
        try self.init(documentNumber: rawDocNum, dateOfBirth: rawDob, dateOfExpiry: rawDoe)
    }
    
    /// Ngày phải gồm đúng 6 chữ số (YYMMDD)
    private static func isValidDateString(_ value: String) -> Bool {
        value.count == 6 && value.allSatisfy(\.isNumber)
    }

    private var paddedDocumentNumber: String {
        guard documentNumber.count < 9 else {  return String(documentNumber.suffix(9)) }
        return documentNumber.padding(toLength: 9, withPad: "<", startingAt: 0)
    }

    /// mrzKey = docNumber(9) + checkDigit + dob(6) + checkDigit + doe(6) + checkDigit
    /// Dùng làm seed cho BAC (SHA-1 -> derive Kenc/Kmac).
    public var mrzKeyString: String {
        let docNumberField = paddedDocumentNumber + String(MRZKey.checkDigit(for: paddedDocumentNumber))
        let dobField = dateOfBirth + String(MRZKey.checkDigit(for: dateOfBirth))
        let doeField = dateOfExpiry + String(MRZKey.checkDigit(for: dateOfExpiry))
        return docNumberField + dobField + doeField
    }
    
    /// Trọng số lặp lại theo thứ tự 7, 3, 1 cho từng ký tự.
    private static let weights: [Int] = [7, 3, 1]

    /// Tính giá trị số của 1 ký tự MRZ
    private static func value(of character: Character) -> Int {
        if let digit = character.wholeNumberValue, character.isNumber {
            return digit
        }
        if let asciiValue = character.asciiValue, character.isLetter {
            // 'A' = 65 -> 10, 'B' = 66 -> 11, ..., 'Z' = 90 -> 35
            return Int(asciiValue) - 55
        }
        return 0 // ký tự đệm '<' hoặc ký tự không hợp lệ khác
    }

    /// Tính check digit (0-9) cho một chuỗi MRZ theo thuật toán trọng số 7-3-1.
    static func checkDigit(for input: String) -> Int {
        var sum = 0
        for (index, character) in input.enumerated() {
            let weight = weights[index % weights.count]
            sum += value(of: character) * weight
        }
        return sum % 10
    }
    
    
    // Build MRZKey bằng cách chụp mặc sau CCCD
    static func buildMRZKey(line1: String, line2: String) -> String? {
        let l1 = Array(line1)
        let l2 = Array(line2)
        guard l1.count >= 15, l2.count >= 15 else { return nil }
        
        // Line 1: [0-1] loại giấy tờ, [2-4] mã quốc gia, [5-13] document number (9 ký tự), [14] check digit
        let documentNumber = String(l1[5...13])
        let docCheckDigit = String(l1[14])
        
        // Line 2: [0-5] ngày sinh (6), [6] check digit, [7] giới tính, [8-13] ngày hết hạn (6), [14] check digit
        let dob = String(l2[0...5])
        let dobCheckDigit = String(l2[6])
        let doe = String(l2[8...13])
        let doeCheckDigit = String(l2[14])
        
        let mrzKey = documentNumber + docCheckDigit + dob + dobCheckDigit + doe + doeCheckDigit
        
        guard validateMRZ(mrz: mrzKey) else {
            return nil
        }
        
        return mrzKey
    }
    
    
    private static func validateMRZ(mrz: String) -> Bool {
        return mrz.count == 24 && mrz.allSatisfy {$0.isNumber}
    }
}
