//  Parse DG2 (EF.DG2) - chứa dữ liệu sinh trắc học khuôn mặt
//  Hỗ trợ trích xuất ảnh định dạng JPEG hoặc JPEG2000.

import Foundation

public struct DG2 {
    // Dữ liệu thô của bức ảnh
    public let imageData: [UInt8]
    
    public init(data: [UInt8]) throws {
        // Parse cấu trúc ASN.1
        let root = try ASN1Node.parse(data)
        
        // Root của DG2 luôn là tag 0x75
        guard root.tag == 0x75 else {
            throw NFCReaderError.responseError("Dữ liệu không phải là DG2 (tag sai)")
        }
        
        // Bên trong 0x75 là 0x7F61
        guard let bht = root.children.first(where: { $0.tag == 0x7F && $0.rawValue.starts(with: [0x61]) }) ??
                          root.children.first(where: { $0.fullBytes.starts(with: [0x7F, 0x61]) }) else {
            throw NFCReaderError.responseError("Không tìm thấy tag 0x7F61 trong DG2")
        }
        
        // Bên trong 0x7F61 là 0x7F60 (Biometric Information Template)
        guard let bit = bht.children.first(where: { $0.tag == 0x7F && $0.rawValue.starts(with: [0x60]) }) ??
                          bht.children.first(where: { $0.fullBytes.starts(with: [0x7F, 0x60]) }) else {
            throw NFCReaderError.responseError("Không tìm thấy Biometric Information Template (0x7F60)")
        }
        
        // Bên trong 0x7F60, ta tìm tag 0x5F2E hoặc 0x7F2E (Biometric Data Block)
        guard let bdb = bit.children.first(where: {
            ($0.tag == 0x5F && $0.rawValue.starts(with: [0x2E])) ||
            ($0.tag == 0x7F && $0.rawValue.starts(with: [0x2E]))
        }) ?? bit.children.first(where: {
            $0.fullBytes.starts(with: [0x5F, 0x2E]) || $0.fullBytes.starts(with: [0x7F, 0x2E])
        }) else {
            throw NFCReaderError.responseError("Không tìm thấy Biometric Data Block (0x5F2E hoặc 0x7F2E)")
        }
        
        // Parse cấu trúc ISO 19794-5 Facial Record Data
        self.imageData = try DG2.parseISO19794_5(data: bdb.rawValue)
    }
    
    private static func parseISO19794_5(data: [UInt8]) throws -> [UInt8] {
        // Kiểm tra header: "FAC\0" (0x46, 0x41, 0x43, 0x00)
        guard data.count > 46, data[0] == 0x46, data[1] == 0x41, data[2] == 0x43, data[3] == 0x00 else {
            throw NFCReaderError.responseError("Biometric Data không đúng chuẩn ISO 19794-5 (Thiếu FAC header)")
        }
        
        // Header dài khoảng 46 byte, sau đó mới là data ảnh.
        let offset = 46
        return try extractFaceImageData(from: data, offset: offset)
    }
    
    private static func extractFaceImageData(from data: [UInt8], offset: Int) throws -> [UInt8] {
        let remaining = Array(data[offset...])
        
        let jpegHeader: [UInt8] = [0xff, 0xd8, 0xff] // Bắt đầu của JPEG
        let jpeg2000CodestreamBitmapHeader: [UInt8] = [0xff, 0x4f, 0xff, 0x51]
        let jpeg2000BitmapHeader: [UInt8] = [0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a]
        
        if remaining.starts(with: jpegHeader) {
            guard let end = findJPEGEnd(in: remaining) else {
                throw NFCReaderError.responseError("Không tìm thấy điểm kết thúc của file JPEG")
            }
            return Array(remaining[..<end])
        }
        
        if remaining.starts(with: jpeg2000CodestreamBitmapHeader) {
            guard let end = findJPEGEnd(in: remaining) else { // J2K codestream end cũng là FFD9
                throw NFCReaderError.responseError("Không tìm thấy điểm kết thúc của file JPEG2000")
            }
            return Array(remaining[..<end])
        }
        
        if remaining.starts(with: jpeg2000BitmapHeader) {
            return try extractJP2BoxData(from: data, offset: offset, maxEnd: data.count)
        }
        
        throw NFCReaderError.responseError("Định dạng ảnh không được hỗ trợ (không phải JPEG hay JP2)")
    }
    
    private static func findJPEGEnd(in data: [UInt8]) -> Int? {
        guard data.count >= 2 else { return nil }
        
        // Tìm EOI marker (FF D9) từ cuối lên
        for i in stride(from: data.count - 2, through: 0, by: -1) {
            if data[i] == 0xFF && data[i + 1] == 0xD9 {
                return i + 2
            }
        }
        return nil
    }
    
    private static func extractJP2BoxData(from data: [UInt8], offset: Int, maxEnd: Int) throws -> [UInt8] {
        var p = offset
        
        while p + 8 <= maxEnd {
            let boxStart = p
            let length = Int(binToInt32(data[p..<p+4]))
            p += 4
            
            let boxType = Array(data[p..<p+4])
            p += 4
            
            let boxEnd: Int
            if length == 0 {
                boxEnd = maxEnd
            } else if length == 1 {
                guard p + 8 <= maxEnd else { break }
                // Bỏ qua đọc length 64-bit cho nhanh vì ảnh thẻ thường không quá 4GB :)
                p += 8
                boxEnd = maxEnd
            } else {
                boxEnd = boxStart + length
            }
            
            guard boxEnd <= maxEnd else { break }
            p = boxEnd
            
            // "jp2c" box (Codestream)
            if boxType == [0x6A, 0x70, 0x32, 0x63] {
                return Array(data[offset..<boxEnd])
            }
        }
        
        throw NFCReaderError.responseError("Lỗi đọc hộp JP2")
    }
    
    private static func binToInt32(_ slice: ArraySlice<UInt8>) -> UInt32 {
        var value: UInt32 = 0
        for byte in slice {
            value = (value << 8) | UInt32(byte)
        }
        return value
    }
}
