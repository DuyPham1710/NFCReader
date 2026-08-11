/*
  Mục đích là để gửi lệnh APDU (Application Protocol Data Unit) qua NFCISO7816Tag và trả về respóne thô (data + status word SW1/SW2). File này KHÔNG biết
  gì về BAC, PACE, hay ý nghĩa nghiệp vụ của từng lệnh - nó chỉ để truyền/nhận byte giữa app và chip

  Các lớp ở tầng trên (BACHandler, PACEHandler, DataGroup readers...) sẽ gọi vào APDUTransceiver để:
    - SELECT FILE   (chọn 1 file trên chip, vd MF, EF.COM, DG1...)
    - READ BINARY   (đọc dữ liệu thô của file đang chọn)
    - GET CHALLENGE (chip sinh 1 số ngẫu nhiên, dùng trong BAC)
    - EXTERNAL/MUTUAL AUTHENTICATE (xác thực 2 chiều BAC/PACE)
 */

import Foundation
import CoreNFC

public final class APDUTransceiver: @unchecked Sendable {

    private let tag: NFCISO7816Tag
    var secureMessaging: SecureMessaging?
    
    public init(tag: NFCISO7816Tag) {
        self.tag = tag
    }

    // Gửi 1 lệnh APDU tới chip.
    // Có bọc SM nếu có
    public func send(apdu: NFCISO7816APDU) async throws -> APDUResponse {
        let apduToSend = try secureMessaging?.protect(apdu: apdu) ?? apdu
        
        let rawResponse = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<APDUResponse, Error>) in
            tag.sendCommand(apdu: apduToSend) { data, sw1, sw2, error in
                if let error = error {
                    continuation.resume(throwing: NFCReaderError.responseError(error.localizedDescription))
                    return
                }
                continuation.resume(returning: APDUResponse(data: data, sw1: sw1, sw2: sw2))
            }
        }
        
        if let sm = secureMessaging {
            return try sm.unprotect(response: rawResponse)
        }
        
        return rawResponse
    }

    /// SELECT FILE (CLA=00, INS=A4) - chọn 1 file trên chip
    public func selectFile(fileId: [UInt8], p1: UInt8 = 0x02, p2: UInt8 = 0x0C) async throws -> APDUResponse {
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00,
            instructionCode: 0xA4,
            p1Parameter: p1,
            p2Parameter: p2,
            data: Data(fileId),
            expectedResponseLength: 256
        )
        return try await send(apdu: apdu)
    }

    /// READ BINARY (CLA=00, INS=B0) - đọc `length` byte dữ liệu của file
    /// đang được chọn (sau khi đã `selectFile`), bắt đầu từ `offset`.
    public func readBinary(offset: Int, length: Int) async throws -> APDUResponse {
        let p1 = UInt8((offset >> 8) & 0xFF)
        let p2 = UInt8(offset & 0xFF)
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00,
            instructionCode: 0xB0,
            p1Parameter: p1,
            p2Parameter: p2,
            data: Data(),
            expectedResponseLength: length
        )
        return try await send(apdu: apdu)
    }

    /// GET CHALLENGE (CLA=00, INS=84) - yêu cầu chip sinh 1 chuỗi ngẫu nhiên
    public func getChallenge(expectedLength: Int = 8) async throws -> APDUResponse {
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00,
            instructionCode: 0x84,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: Data(),
            expectedResponseLength: expectedLength
        )
        return try await send(apdu: apdu)
    }

    /// EXTERNAL  AUTHENTICATE (CLA=00, INS=82) - gửi dữ liệu đã mã hoá/MAC
   public func externalAuthenticate(data: Data, expectedResponseLength: Int = 256) async throws -> APDUResponse {
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00,
            instructionCode: 0x82,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: data,
            expectedResponseLength: expectedResponseLength
        )
        return try await send(apdu: apdu)
    }
    
    /// MSE:Set AT (Manage Security Environment: Set Authentication Template)
    /// Dùng trong Chip Authentication để cấu hình môi trường xác thực
    public func sendMSESetATIntAuth(oid: String, keyId: Int?) async throws -> APDUResponse {
        let oidBytes = oidToBytes(oid: oid, replaceTag: true) // Đổi tag 0x06 thành 0x80
        
        var dataBytes = oidBytes
        if let keyId = keyId, keyId != 0 {
            let keyIdBytes = inToBin(keyId)
            let wrappedKeyId = wrapDO(b: 0x84, arr: keyIdBytes)
            dataBytes += wrappedKeyId
        }
        
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00,
            instructionCode: 0x22,  // 0x22: MSE
            p1Parameter: 0x41,      // 0x41: Set
            p2Parameter: 0xA4,      // 0xA4: AT (Authentication Template)
            data: Data(dataBytes),
            expectedResponseLength: 256
        )
        return try await send(apdu: apdu)
    }

    /// GENERAL AUTHENTICATE (CLA=00, INS=86)
    /// Gửi public key của điện thoại tới chip để thực hiện ECDH trong CA.
    /// Có thể dùng Command Chaining (CLA=0x10) nếu dữ liệu quá dài.
    public func sendGeneralAuthenticate(data: [UInt8], isLast: Bool, expectedResponseLength: Int = 256) async throws -> APDUResponse {
        // Gói dữ liệu vào tag 0x7C (Dynamic Authentication Data)
        let wrappedData = wrapDO(b: 0x7C, arr: data)
        let commandData = Data(wrappedData)
        
        // Nếu dữ liệu dài, phải dùng command chaining (chia nhỏ thành nhiều lệnh)
        // 0x10 là cờ command chaining, 0x00 là lệnh cuối cùng
        let instructionClass: UInt8 = isLast ? 0x00 : 0x10
        
        let apdu = NFCISO7816APDU(
            instructionClass: instructionClass,
            instructionCode: 0x86, // 0x86: GENERAL AUTHENTICATE
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: commandData,
            expectedResponseLength: expectedResponseLength
        )
        
        return try await send(apdu: apdu)
    }
}
