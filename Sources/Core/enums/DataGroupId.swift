import Foundation

public enum DataGroupId: String, Sendable {
    case COM, SOD
    case DG1, DG2, DG3, DG4, DG5, DG6, DG7, DG8, DG9, DG10, DG11, DG12, DG13, DG14, DG15, DG16
    
    public var fileId: [UInt8] {
        switch self {
        case .COM:  return [0x01, 0x1E]
        case .SOD:  return [0x01, 0x1D]
        case .DG1:  return [0x01, 0x01]
        case .DG2:  return [0x01, 0x02]
        case .DG3:  return [0x01, 0x03]
        case .DG4:  return [0x01, 0x04]
        case .DG5:  return [0x01, 0x05]
        case .DG6:  return [0x01, 0x06]
        case .DG7:  return [0x01, 0x07]
        case .DG8:  return [0x01, 0x08]
        case .DG9:  return [0x01, 0x09]
        case .DG10: return [0x01, 0x0A]
        case .DG11: return [0x01, 0x0B]
        case .DG12: return [0x01, 0x0C]
        case .DG13: return [0x01, 0x0D]
        case .DG14: return [0x01, 0x0E]
        case .DG15: return [0x01, 0x0F]
        case .DG16: return [0x01, 0x10]
        }
    }
}
    

extension DataGroupId {
    var viFriendlyName: String {
        switch self {
        case .COM: return "thông tin chung"
        case .DG1: return "thông tin cá nhân"
        case .DG2: return "hình ảnh"
        case .DG13: return "dữ liệu bổ sung"
        case .SOD: return "chữ ký bảo mật"
        default: return "dữ liệu"
        }
    }
    var enFriendlyName: String {
        switch self {
        case .COM: return "general info"
        case .DG1: return "personal info"
        case .DG2: return "photo"
        case .DG13: return "additional data"
        case .SOD: return "security signature"
        default: return "data"
        }
    }
}

