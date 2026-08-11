//
//  DataGroup1.swift
//  NFCReader
//
//  Parse DG1 (EF.DG1) - chứa dữ liệu MRZ đầy đủ, định dạng TD1 (dùng cho thẻ
//  căn cước/ID card, khác TD3 dùng cho hộ chiếu): 3 dòng x 30 ký tự = 90 byte.
//
//  Cấu trúc:
//    '61' L
//        '5F1F' Lm <chuỗi MRZ thô 90 ký tự ASCII>
//
//  Layout TD1 (ICAO 9303 Part 5):
//    Dòng 1 (30 ký tự): documentCode(2) issuingState(3) documentNumber(9) checkDigit(1) optionalData(15)
//    Dòng 2 (30 ký tự): dateOfBirth(6) checkDigit(1) sex(1) dateOfExpiry(6) checkDigit(1) nationality(3) optionalData(11) compositeCheckDigit(1)
//    Dòng 3 (30 ký tự): tên đầy đủ, định dạng "HỌ<<TÊN<ĐỆM<TÊN" (đệm bằng '<')
//

import Foundation

public struct DG1 {
    public let documentCode: String
    public let issuingState: String
    public let documentNumber: String
    public let dateOfBirth: String      // YYMMDD
    public let sex: String              // "M" / "F" / "<" (không xác định)
    public let dateOfExpiry: String     // YYMMDD
    public let nationality: String
    public let surname: String
    public let givenNames: String

    /// Chuỗi MRZ thô đầy đủ 90 ký tự, giữ lại để đối chiếu/debug hoặc verify check digit sau này.
    public let rawMRZ: String

    public init(data: [UInt8]) throws {
        var offset = 0

        guard !data.isEmpty, data[offset] == 0x61 else {
            throw NFCReaderError.responseError("DG1 Malformed: thiếu tag 0x61")
        }
        offset += 1

        let outerLength = try asn1Length(Array(data[offset...]))
        offset += outerLength.offset
        let contentEnd = offset + outerLength.length
        guard contentEnd <= data.count else {
            throw NFCReaderError.responseError("DG1 Malformed: length vượt quá dữ liệu thực tế")
        }

        guard offset < contentEnd, data[offset] == 0x5F, offset + 1 < contentEnd, data[offset + 1] == 0x1F else {
            throw NFCReaderError.responseError("DG1 Malformed: thiếu tag 0x5F1F (MRZ data)")
        }
        offset += 2

        let mrzLengthResult = try asn1Length(Array(data[offset...]))
        offset += mrzLengthResult.offset
        guard offset + mrzLengthResult.length <= data.count else {
            throw NFCReaderError.responseError("DG1 Malformed: length MRZ vượt quá dữ liệu thực tế")
        }

        let mrzBytes = Array(data[offset..<(offset + mrzLengthResult.length)])
        guard let mrzString = String(bytes: mrzBytes, encoding: .ascii), mrzString.count == 90 else {
            throw NFCReaderError.responseError("DG1 Malformed: MRZ không đúng 90 ký tự (TD1)")
        }
        self.rawMRZ = mrzString

        let chars = Array(mrzString)
        let line1 = String(chars[0..<30])
        let line2 = String(chars[30..<60])
        let line3 = String(chars[60..<90])

        // --- Dòng 1 ---
        let l1 = Array(line1)
        self.documentCode = String(l1[0..<2]).replacingOccurrences(of: "<", with: "")
        self.issuingState = String(l1[2..<5])
        self.documentNumber = String(l1[5..<14]).replacingOccurrences(of: "<", with: "")
        // l1[14] = check digit của documentNumber, l1[15..<30] = optional data - bỏ qua ở bước này

        // --- Dòng 2 ---
        let l2 = Array(line2)
        self.dateOfBirth = String(l2[0..<6])
        // l2[6] = check digit ngày sinh
        self.sex = String(l2[7])
        self.dateOfExpiry = String(l2[8..<14])
        // l2[14] = check digit ngày hết hạn
        self.nationality = String(l2[15..<18])
        // l2[18..<29] = optional data, l2[29] = composite check digit - bỏ qua ở bước này

        // --- Dòng 3: tên, định dạng "HỌ<<TÊN_ĐỆM<TÊN" ---
        let nameParts = line3
            .split(separator: "<", omittingEmptySubsequences: false)
            .map(String.init)

        // Phần trước "<<" đầu tiên là họ, phần sau là tên (có thể gồm nhiều từ, ngăn bởi '<' đơn)
        if let doubleSeparatorIndex = line3.range(of: "<<") {
            let surnamePart = String(line3[line3.startIndex..<doubleSeparatorIndex.lowerBound])
            let givenNamePart = String(line3[doubleSeparatorIndex.upperBound...])
            self.surname = surnamePart
            self.givenNames = givenNamePart
                .split(separator: "<", omittingEmptySubsequences: true)
                .joined(separator: " ")
        } else {
            // Trường hợp bất thường không có "<<" - fallback lấy toàn bộ, bỏ ký tự đệm
            self.surname = nameParts.first ?? ""
            self.givenNames = nameParts.dropFirst().joined(separator: " ")
        }
    }
}
