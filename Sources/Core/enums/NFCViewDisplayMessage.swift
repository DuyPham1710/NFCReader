public enum NFCViewDisplayMessage {
    case requestPresentCard
    case authenticatingWithCard(Int)
    case readingDataGroupProgress(DataGroupId, Int)
    case error(NFCReaderError)
    case successfulRead
    
    // Thứ tự các bước để tính chấm tiến trình
    private static let totalSteps = 5 // authenticating, DG1, DG2, DG13, SOD

    private var currentStepIndex: Int {
        switch self {
        case .authenticatingWithCard: return 1
        case .readingDataGroupProgress(let dg, _):
            switch dg {
            case .DG1: return 2
            case .DG2: return 3
            case .DG13: return 4
            case .SOD: return 5
            default: return 1
            }
        case .successfulRead: return Self.totalSteps
        default: return 0
        }
    }

    private var dotsLine: String {
        (1...Self.totalSteps)
            .map { $0 <= currentStepIndex ? "🔵" : "⚪" }
            .joined(separator: "  ")
    }
        // 🟢
    func description(customMessageHandler: ((NFCViewDisplayMessage) -> String?)?) -> String {
        if let custom = customMessageHandler?(self) {
           return custom
        }
        switch NFCReaderLanguage.current {
        case .vi:
            return viDescription
        case .en:
            return enDescription
        }
    }
    
    private var viDescription: String {
        switch self {
        case .requestPresentCard:
            return "Chạm Chip của CCCD vào\nmặt sau điện thoại"
        case .authenticatingWithCard:
            return "Vui lòng giữ nguyên CCCD"
        case .readingDataGroupProgress(let dg, _):
            return "Đang đọc \(dg.viFriendlyName)...\n\(dotsLine)"
        case .error(let err):
            return err.localizedDescription(language: .vi)
        case .successfulRead:
            return "Đọc NFC thành công!"
        }
    }
 
    private var enDescription: String {
        switch self {
        case .requestPresentCard:
            return "Tap your ID card against\nthe back of your phone"
        case .authenticatingWithCard:
            return "Please hold your ID steady"
        case .readingDataGroupProgress(let dg, _):
            return "Reading \(dg.enFriendlyName)...\n\(dotsLine)"
        case .error(let err):
            return err.localizedDescription(language: .en)
        case .successfulRead:
            return "Successfully read ID card data"
        }
    }

}
