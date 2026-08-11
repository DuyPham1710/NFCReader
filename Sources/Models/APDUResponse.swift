import Foundation

public struct APDUResponse {
    public let data: Data
    public let sw1: UInt8
    public let sw2: UInt8

    /// Chip trả về status thành công khi SW1SW2 == 9000.
    public var isSuccess: Bool {
        sw1 == 0x90 && sw2 == 0x00
    }

    public var statusWordHex: String {
        String(format: "%02X%02X", sw1, sw2)
    }
}
