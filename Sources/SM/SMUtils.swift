//    public func unprotect(response: APDUResponse) throws -> APDUResponse {
//        // Nếu lỗi
//        if response.sw1 != 0x90 || response.sw2 != 0x00 {
//            return response
//        }
//
//        self.ssc = incSSC()
//
//        let padSSC = algoName == .DES ? self.ssc : [UInt8](repeating: 0, count: 8) + self.ssc
//
//        let rapduBin = [UInt8](response.data) + [response.sw1, response.sw2]
//        var offset = 0
//        var needCC = false
//        var do87: [UInt8] = []
//        var do87Data: [UInt8] = []
//        var do99: [UInt8] = []
//
//        // Parse DO87 (Payload mã hoá)
//        if !rapduBin.isEmpty && rapduBin[offset] == 0x87 {
//           let lengthResult = try asn1Length(Array(rapduBin[(offset+1)...]))
//           let encDataLength = lengthResult.length
//           let lengthOfLength = lengthResult.offset
//
//           offset += 1 + lengthOfLength
//
//           if rapduBin[offset] != 0x01 {
//               throw NFCReaderError.responseError("Lỗi giải mã SM: D087 Malformed")
//           }
//
//           let do87TotalLength = 1 + lengthOfLength + encDataLength
//           do87 = Array(rapduBin[0..<do87TotalLength])
//           do87Data = Array(rapduBin[(offset+1)..<(offset+encDataLength)]) // Skip 0x01 byte
//           offset += encDataLength
//           needCC = true
//        }
//
//        // Parse DO99 (Status Words gốc)
//        guard rapduBin.count >= offset + 4 else {
//           let sw1 = rapduBin.count >= offset + 3 ? rapduBin[offset + 2] : 0
//           let sw2 = rapduBin.count >= offset + 4 ? rapduBin[offset + 3] : 0
//           return APDUResponse(data: Data(), sw1: sw1, sw2: sw2)
//        }
//
//        do99 = Array(rapduBin[offset..<(offset+4)])
//        let sw1 = rapduBin[offset+2]
//        let sw2 = rapduBin[offset+3]
//        offset += 4
//        needCC = true
//
//        if do99[0] != 0x99 || do99[1] != 0x02 {
//           //return APDUResponse(data: Data(), sw1: sw1, sw2: sw2)
//            throw NFCReaderError.responseError("Lỗi bảo mật: DO'99' sai định dạng, response không đáng tin cậy")
//        }
//
//        // Parse DO8E (Verify MAC)
//        if offset < rapduBin.count, rapduBin[offset] == 0x8E {
//           let ccLength = Int(rapduBin[offset+1])
//           let cc = Array(rapduBin[(offset+2)..<(offset+2+ccLength)])
//
//           // Tính lại MAC để so sánh
//           let dataToSign = pad(padSSC + do87 + do99, blockSize: padLength)
//           let macResultAll = MAC(algoName: algoName, key: sessionMacKey, msg: dataToSign)
//           let expectedCC = Array(macResultAll[0..<8]) // Dù là AES hay DES thì chữ ký luôn cắt còn 8 byte
//
//           if cc != expectedCC {
//               throw NFCReaderError.responseError("Lỗi bảo mật: Secure Messaging MAC Verification Failed!")
//           }
//        } else if needCC {
//           throw NFCReaderError.responseError("Lỗi bảo mật: Chip không trả về chữ ký MAC (DO8E) bắt buộc.")
//        }
//
//        // Decrypt DO87
//        var decryptedData: [UInt8] = []
//        if !do87Data.isEmpty {
//           if algoName == .DES {
//               let iv = [UInt8](repeating: 0, count: 8)
//               let dec = tripleDESDecrypt(key: sessionEncKey, message: do87Data, iv: iv)
//               decryptedData = unpad(dec)
//           } else {
//               let paddedSSC = [UInt8](repeating: 0, count: 8) + self.ssc
//               let iv = AESECBEncrypt(key: sessionEncKey, message: padSSC)
//               let dec = AESDecrypt(key: sessionEncKey, message: do87Data, iv: iv)
//               decryptedData = unpad(dec)
//           }
//        }
//
//        return APDUResponse(data: Data(decryptedData), sw1: sw1, sw2: sw2)
//    }
