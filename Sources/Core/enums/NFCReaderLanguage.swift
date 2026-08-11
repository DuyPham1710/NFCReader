import Foundation
 
public enum NFCReaderLanguage {
    case vi
    case en
    
    public static var current: NFCReaderLanguage {
       let preferred = Locale.preferredLanguages.first ?? "en"
       return preferred.hasPrefix("vi") ? .vi : .en
   }
}
