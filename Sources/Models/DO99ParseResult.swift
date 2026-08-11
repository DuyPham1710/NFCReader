public enum DO99ParseResult {
    case success(rawBlock: [UInt8], sw1: UInt8, sw2: UInt8, nextOffset: Int)
    // Response quá ngắn/bất thường - trả sw1/sw2 tạm, không tiếp tục xử lý MAC/decrypt.
    case malformed(sw1: UInt8, sw2: UInt8)
}
