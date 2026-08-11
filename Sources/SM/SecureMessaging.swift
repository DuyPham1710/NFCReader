import Foundation
import CoreNFC

public class SecureMessaging {
    private var sessionEncKey: [UInt8]
    private var sessionMacKey: [UInt8]
    private var ssc: [UInt8]
    public let algoName: EncryptAlgorithm
    private let padLength: Int
    public init(algoName: EncryptAlgorithm = .DES, sessionEncKey: [UInt8], sessionMacKey: [UInt8], ssc: [UInt8]) {
        self.sessionEncKey = sessionEncKey
        self.sessionMacKey = sessionMacKey
        self.ssc = ssc
        self.algoName = algoName
        self.padLength = (algoName == .DES) ? 8 : 16
    }
    
    public func protect(apdu: NFCISO7816APDU) throws -> NFCISO7816APDU {
        self.ssc = incSSC()
        
        // AES yêu cầu SSC dài 16 bytes
        let padSSC = (algoName == .DES) ? self.ssc : [UInt8](repeating: 0, count: 8) + self.ssc
        
        let cmdHeader = maskClassAndPad(apdu: apdu)
        
       
        let do87 = try builDO87(apdu: apdu)      // Build DO87 (mã hoá payload nếu có)
        let do97 = try builDO97(apdu: apdu)     // Build DO97 (Khai báo độ dài mong đợi nhận về)
       
        let rawInput = cmdHeader + do87 + do97
        
        let dataToSign = pad(padSSC + rawInput, blockSize: padLength)
        
        let macResultAll = MAC(algoName: algoName, key: sessionMacKey, msg: dataToSign)
        let macResult = Array(macResultAll[0..<8]) // MAC lấy 8 bytes
        let do8E = buildDO8E(mac: macResult)

        // Đóng gói lại thành lệnh APDU bảo mật
        let protectedPayload = do87 + do97 + do8E

        return NFCISO7816APDU(
           instructionClass: 0x0C,
           instructionCode: apdu.instructionCode,
           p1Parameter: apdu.p1Parameter,
           p2Parameter: apdu.p2Parameter,
           data: Data(protectedPayload),
           expectedResponseLength: 256 // Luôn dùng 256 (tương đương 0x00) cho Secure Messaging response
        )
        
    }
    
    public func unprotect(response: APDUResponse) throws -> APDUResponse {
        // Nếu lỗi
        guard response.sw1 == 0x90, response.sw2 == 0x00 else {
            return response
        }

        self.ssc = incSSC()
        let padSSC = algoName == .DES ? self.ssc : [UInt8](repeating: 0, count: 8) + self.ssc

        let rapduBin = [UInt8](response.data) + [response.sw1, response.sw2]
        var offset = 0

        // Parse DO87 (1 số lệnh chip chỉ trả về status chứ không có data)
        let do87Result = try parseDO87(from: rapduBin, startingAt: offset)
        
        if let do87Result = do87Result {
            offset = do87Result.nextOffset
        }
        
        let isMACRequired = do87Result != nil

        // Parse DO99
        let do99 = parseDO99(from: rapduBin, startingAt: offset)
        guard case .success(let do99RawBlock, let sw1, let sw2, let nextOffset) = do99 else {
            if case .malformed(let sw1, let sw2) = do99 {
                return APDUResponse(data: Data(), sw1: sw1, sw2: sw2)
            }
            return APDUResponse(data: Data(), sw1: 0, sw2: 0)
        }
        offset = nextOffset

        // Verify MAC (DO8E)
        try verifyMAC(
            rapduBin: rapduBin,
            offset: offset,
            padSSC: padSSC,
            do87RawBlock: do87Result?.rawBlock ?? [],
            do99RawBlock: do99RawBlock,
            isRequired: isMACRequired
        )

        // Giải mã DO87 data (nếu có)
        let decryptedData = decryptDO87Data(do87Result?.cipherData ?? [], padSSC: padSSC)

        return APDUResponse(data: Data(decryptedData), sw1: sw1, sw2: sw2)
    }
    
    
    private func parseDO87(from rapduBin: [UInt8], startingAt offset: Int) throws -> DO87ParseResult? {
        guard !rapduBin.isEmpty, offset < rapduBin.count, rapduBin[offset] == 0x87 else {
            return nil
        }

        let lengthResult = try asn1Length(Array(rapduBin[(offset + 1)...]))
        let encDataLength = lengthResult.length
        let lengthOfLength = lengthResult.offset

        var cursor = offset + 1 + lengthOfLength        // trỏ thẳng tới cờ 0x01 (bỏ qua tag + len)

        guard cursor < rapduBin.count, rapduBin[cursor] == 0x01 else {
            throw NFCReaderError.responseError("Lỗi giải mã SM: DO'87' Malformed (thiếu cờ 0x01)")
        }

        let totalLength = 1 + lengthOfLength + encDataLength
        guard offset + totalLength <= rapduBin.count else {
            throw NFCReaderError.responseError("Lỗi giải mã SM: DO'87' Malformed (thiếu dữ liệu)")
        }

        let rawBlock = Array(rapduBin[offset..<(offset + totalLength)])
        let cipherData = Array(rapduBin[(cursor + 1)..<(offset + totalLength)])
        cursor = offset + totalLength

        return DO87ParseResult(rawBlock: rawBlock, cipherData: cipherData, nextOffset: cursor)
    }

    /// Parse DO'99' (4 byte cố định: 0x99 0x02 SW1 SW2), bắt buộc phải có trong mọi response.
    private func parseDO99(from rapduBin: [UInt8], startingAt offset: Int) -> DO99ParseResult {
        guard rapduBin.count >= offset + 4 else {
            let sw1: UInt8 = rapduBin.count >= offset + 3 ? rapduBin[offset + 2] : 0
            let sw2: UInt8 = 0 // không đủ byte để đọc SW2, response bất thường
            return .malformed(sw1: sw1, sw2: sw2)
        }

        let rawBlock = Array(rapduBin[offset..<(offset + 4)])
        guard rawBlock[0] == 0x99, rawBlock[1] == 0x02 else {
            return .malformed(sw1: rawBlock[2], sw2: rawBlock[3])
        }

        return .success(rawBlock: rawBlock, sw1: rawBlock[2], sw2: rawBlock[3], nextOffset: offset + 4)
    }

    private func verifyMAC(
        rapduBin: [UInt8],
        offset: Int,
        padSSC: [UInt8],
        do87RawBlock: [UInt8],
        do99RawBlock: [UInt8],
        isRequired: Bool
    ) throws {
        guard offset < rapduBin.count, rapduBin[offset] == 0x8E else {
            if isRequired {
                throw NFCReaderError.responseError("Lỗi bảo mật: Chip không trả về chữ ký MAC (DO'8E') bắt buộc.")
            }
            return
        }

        let macLength = Int(rapduBin[offset + 1])
        guard offset + 2 + macLength <= rapduBin.count else {
            throw NFCReaderError.responseError("Lỗi bảo mật: DO'8E' thiếu dữ liệu.")
        }
        let chipMac = Array(rapduBin[(offset + 2)..<(offset + 2 + macLength)])

        let dataToSign = pad(padSSC + do87RawBlock + do99RawBlock, blockSize: padLength)
        let macResultAll = MAC(algoName: algoName, key: sessionMacKey, msg: dataToSign)
        let expectedMac = Array(macResultAll[0..<8]) // MAC luôn cắt còn 8 byte, cả DES lẫn AES

        guard chipMac == expectedMac else {
            throw NFCReaderError.responseError("Lỗi bảo mật: Secure Messaging MAC Verification Failed!")
        }
    }

    /// Giải mã phần ciphertext trong DO87
    private func decryptDO87Data(_ cipherData: [UInt8], padSSC: [UInt8]) -> [UInt8] {
        guard !cipherData.isEmpty else { return [] }

        let decrypted: [UInt8]
        if algoName == .DES {
            let iv = [UInt8](repeating: 0, count: 8)
            decrypted = tripleDESDecrypt(key: sessionEncKey, message: cipherData, iv: iv)
        } else {
            let iv = AESECBEncrypt(key: sessionEncKey, message: padSSC)
            decrypted = AESDecrypt(key: sessionEncKey, message: cipherData, iv: iv)
        }
        return unpad(decrypted)
    }
    
    
    
    private func builDO97(apdu: NFCISO7816APDU) throws -> [UInt8] {
        let le = apdu.expectedResponseLength
        guard le > 0 else { return [] }
        
        var binLe = inToBin(le)
        if le == 256 { binLe = [0x00] } // 256 in APDU length is represented as 0x00
        return [0x97] + toAsn1Length(binLe.count) + binLe
    }
    
    private func buildDO8E(mac: [UInt8]) -> [UInt8] {
       return [0x8E, UInt8(mac.count)] + mac
   }
    
    private func builDO87(apdu: NFCISO7816APDU) throws -> [UInt8] {
        guard let data = apdu.data, !data.isEmpty else { return [] }
        
        let padData = pad([UInt8](data), blockSize: padLength)
        
        let encrypted: [UInt8]
        if algoName == .DES {
            encrypted = tripleDESEncrypt(key: sessionEncKey, message: padData, iv: [UInt8](repeating: 0, count: 8))
        } else {
            let padSSC = [UInt8](repeating: 0, count: 8) + self.ssc
            let iv = AESECBEncrypt(key: sessionEncKey, message: padSSC)
            encrypted = AESEncrypt(key: sessionEncKey, message: padData, iv: iv)
        }
        
        let cipher = [0x01] + encrypted     // 0x01 là cờ đánh dấu dữ liệu đã pad
        return [0x87] + toAsn1Length(cipher.count) + cipher
    }
    
    private func maskClassAndPad(apdu : NFCISO7816APDU ) -> [UInt8] {
        let res = pad([0x0C, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter], blockSize: padLength)
        return res
    }
    
    private func incSSC() -> [UInt8] {
        var newSSC = self.ssc
        
        for i in (0..<ssc.count).reversed() {
            if newSSC[i] == 255 {
                newSSC[i] = 0
            } else {
                newSSC[i] += 1
                break
            }
        }
        return newSSC
    }
}
