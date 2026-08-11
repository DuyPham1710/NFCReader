import Foundation

public struct NFCCardModel: Encodable {
    public let documentNumber: String
    public let fullName: String
    public let dateOfBirth: String
    public let dateOfExpiry: String
    public let sex: String
    public let nationality: String
    
    // Các thông tin chỉ có ở CCCD Việt Nam (DG13)
    public let ethnicity: String?
    public let religion: String?
    public let hometown: String?
    public let permanentAddress: String?
    public let dateOfIssue: String?
    public let fatherName: String?
    public let motherName: String?
    public let personalCharacteristics: String?
    
    // Ảnh khuôn mặt (Từ DG2)
    public let faceImageData: [UInt8]?
    
    public var passiveAuthSuccess: Bool = false
    public var c06Verified: Bool = false
    
    enum CodingKeys: String, CodingKey {
        case documentNumber, fullName, dateOfBirth, dateOfExpiry, sex, nationality
        case ethnicity, religion, hometown, permanentAddress, dateOfIssue
        case fatherName, motherName, personalCharacteristics, passiveAuthSuccess, c06Verified
    }
    
    public init(dg1: DG1, dg13: DG13?, dg2: DG2) {
        // Ưu tiên lấy từ DG13 (tiếng Việt có dấu), nếu thẻ không có DG13 (VD: Hộ chiếu) thì fallback về DG1 (tiếng Anh/không dấu)
        self.documentNumber = dg13?.documentNumber ?? dg1.documentNumber
        self.fullName = dg13?.fullName ?? "\(dg1.surname) \(dg1.givenNames)"
        self.dateOfBirth = dg13?.dateOfBirth ?? dg1.dateOfBirth
        self.dateOfExpiry = dg13?.dateOfExpiry ?? dg1.dateOfExpiry
        self.sex = dg13?.sex ?? dg1.sex
        self.nationality = dg13?.nationality ?? dg1.nationality
        
        self.ethnicity = dg13?.ethnicity
        self.religion = dg13?.religion
        self.hometown = dg13?.hometown
        self.permanentAddress = dg13?.permanentAddress
        self.dateOfIssue = dg13?.dateOfIssue
        self.fatherName = dg13?.fatherName
        self.motherName = dg13?.motherName
        self.personalCharacteristics = dg13?.personalCharacteristics
        
        self.faceImageData = dg2.imageData
    }
    
    public func printFormattedText() {
            print("""
            ==================================================
            THÔNG TIN THẺ CĂN CƯỚC CÔNG DÂN (TEXT)
            ==================================================
            • Số CCCD                 : \(documentNumber)
            • Họ và tên               : \(fullName)
            • Ngày sinh               : \(dateOfBirth)
            • Giới tính               : \(sex)
            • Quốc tịch               : \(nationality)
            • Dân tộc                 : \(ethnicity ?? "-")
            • Tôn giáo                : \(religion ?? "-")
            • Quê quán                : \(hometown ?? "-")
            • Nơi thường trú          : \(permanentAddress ?? "-")
            • Đặc điểm nhận dạng     : \(personalCharacteristics ?? "-")
            • Ngày cấp                : \(dateOfIssue ?? "-")
            • Ngày hết hạn            : \(dateOfExpiry)
            • Bố / Mẹ                 : \(fatherName ?? "-") / \(motherName ?? "-")
            • Trạng thái PA (Local)   : \(passiveAuthSuccess ? "VALID" : "INVALID")
            • Xác thực C06             : \(c06Verified ? "VALID" : "INVALID")
            ==================================================
            """)
        }
    
    public func printFormattedJSON() {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            
            do {
                let jsonData = try encoder.encode(self)
                if let jsonString = String(data: jsonData, encoding: .utf8) {
                    print("""
                    ==================================================
                    THÔNG TIN DỮ LIỆU DẠNG JSON
                    ==================================================
                    \(jsonString)
                    ==================================================
                    """)
                }
            } catch {
                print("[NFCReader] Lỗi khi convert sang JSON: \(error.localizedDescription)")
            }
        }
}
