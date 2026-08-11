public struct DO87ParseResult {
    let rawBlock: [UInt8]       // toàn bộ khối DO87 gốc (tag + length + 0x01 + ciphertext), dùng để verify MAC
    let cipherData: [UInt8]     // chỉ phần ciphertext thật, dùng để giải mã
    let nextOffset: Int         // vị trí offset sau khi đọc xong DO87
}
