import Foundation

public enum NFCReaderError: Error, LocalizedError {
    case notSupported
    case userCanceled
    case timeout
    case connectionError
    case invalidMRZKey
    case tagNotValid
    case moreThanOneTagFound
    case responseError(String)
    case unknown(Error?)
    
    public var errorDescription: String? {
        localizedDescription(language: .current)
    }
    
    public func localizedDescription(language: NFCReaderLanguage) -> String {
        switch language {
        case .vi: return viDescription
        case .en: return enDescription
        }
    }
 
    private var viDescription: String {
        switch self {
        case .notSupported:
            return "Thiết bị không hỗ trợ quét CCCD bằng NFC."
        case .userCanceled:
            return "Bạn đã huỷ quá trình quét CCCD."
        case .timeout:
            return "hết thời gian quét CCCD. Vui lòng thử lại."
        case .connectionError:
            return "Không thể kết nối với chip trên CCCD. Hãy đặt CCCD sát mặt lưng thiết bị và thử lại."
        case .invalidMRZKey:
            return "Không thể đọc thông tin từ CCCD. Vui lòng kiểm tra lại thông tin và thử lại."
        case .tagNotValid:
            return "Không phát hiện được CCCD hợp lệ. Vui lòng kiểm tra và thử lại."
        case .moreThanOneTagFound:
            return "Phát hiện nhiều thẻ. Vui lòng chỉ đặt một CCCD gần thiét vị và thử lại."
        case .responseError(let msg):
          //  return "Lỗi phản hồi từ chip: \(msg)"
            return "Không thẻ đọc dữ liệu từ CCCD. Vui lòng thử lại."
        case .unknown(let err):
           // return "Lỗi không xác định: \(err?.localizedDescription ?? "N/A")"
            return "Đã xảy ra lỗi. Vui lòng thử lại sau."
        }
    }
 
    private var enDescription: String {
        switch self {
        case .notSupported:
            return "This device does not support NFC scanning for ID cards."
        case .userCanceled:
            return "The user canceled the scan session."
        case .timeout:
            return "ID scanning timed out. Please try again."
        case .connectionError:
            return "Unable to connect to the chip on the ID card. Place the card against the back of your device and try again."
        case .invalidMRZKey:
            return "Unable to read the ID card. Please check the information and try again."
        case .tagNotValid:
            return "No valid ID card detected. Please check the card and try again."
        case .moreThanOneTagFound:
            return "Multiple cards detected. Please place only one ID card near your device and try again."
        case .responseError(let msg):
           // return "Error response from chip: \(msg)"
            return "Unable to read data from the ID card. Please try again."
        case .unknown(let err):
           // return "Unknown error: \(err?.localizedDescription ?? "N/A")"
            return "An error occurred. Please try again later."
        }
    }

    
}
