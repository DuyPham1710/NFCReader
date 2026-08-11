import Foundation

public class BACHandler {
    private var kenc: [UInt8] = []
    private var kmac:  [UInt8] = []
    private var chipChallenge: [UInt8] = []
    private var appChallenge: [UInt8] = []
    private var appSecretShare: [UInt8] = []
    
    private let transceiver: APDUTransceiver?

    
    public init(transceiver: APDUTransceiver) {
        self.transceiver = transceiver
    }
    
    public func performBACAndGetSessionKeys(mrzKey: MRZKey) async throws {
       
        guard let transceiver = self.transceiver else {
            throw NFCReaderError.connectionError
        }
        
        // sinh key từ MRZ
        let mrzKeyString = mrzKey.mrzKeyString
        print("[BAC] Derive keys từ MRZ: \(mrzKeyString)")
        
        let keySeed = deriveKeySeed(from: mrzKeyString)
        print("[BAC] keySeed = \(keySeed)")
        
        let keyGen = SessionKeyGenerator()
        self.kenc = try keyGen.deriveKey(keySeed: keySeed, mode: .ENC_MODE)
        self.kmac = try keyGen.deriveKey(keySeed: keySeed, mode: .MAC_MODE)
        
        print("[BAC] kenc = \(binToHexRep(Array(kenc)))")
        print("[BAC] kmac = \(binToHexRep(Array(kmac)))")
        
        transceiver.secureMessaging = nil
        
        // Get Challenge
        // Nhận về chipChallenge từ chip
        print("[BAC] Gửi Get Challenge...")
        let challengeResponse = try await transceiver.getChallenge()
        
        guard challengeResponse.isSuccess, challengeResponse.data.count == 8 else {
            throw NFCReaderError.responseError("Get Challenge thất bại: SW=\(challengeResponse.statusWordHex)")
        }
            
        self.chipChallenge = [UInt8](challengeResponse.data)
        print("[BAC] chipChallenge = \(binToHexRep(chipChallenge))")

        // App tự tạo appChallengen (8 bytes) và appSecretShare (16 bytes)
        self.appChallenge = generateRandomBytes(8)
        self.appSecretShare = generateRandomBytes(16)
        print("[BAC] App tự tạo appChallengen (8 bytes) và appSecretShare (16 bytes)")
        print("[BAC] appChallenge = \(binToHexRep(appChallenge))")
        print("[BAC] appSecretShare = \(binToHexRep(appSecretShare))")
        
        let authPlainText = appChallenge + chipChallenge + appSecretShare
        print("[BAC] authPlainText = \(binToHexRep(authPlainText))")
        
        // Tính auth_token = 3DES(authPlainText, kenc)
        let iv: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let authToken = tripleDESEncrypt(key: kenc, message: authPlainText, iv: iv)
        print("[BAC] authToken = \(binToHexRep(authToken))")

    
        // authTag = DES_Retail_MAC(Kmac, pad(authToken))
        let authMAC = MAC(algoName: .DES, key: kmac, msg: pad(authToken, blockSize: 8))
        print("[BAC] authMAC = \(binToHexRep(authMAC))")
        
        // Gửi External Authenticate (authToken (32 bytes) + authMAC (8 bytes))
        let cmdData = authToken + authMAC
        
        print("[BAC] Gửi External Authentication (40 bytes)...")
        let response = try await transceiver.externalAuthenticate(data: Data(cmdData))
        guard response.isSuccess, response.data.count > 0 else {
            throw NFCReaderError.responseError("MUTUAL AUTH thất bại: SW=\(response.statusWordHex). Có thể MRZ sai!")
        }
        
        
        let responseData = [UInt8](response.data)
        print("[BAC] response = \(binToHexRep(responseData))")
        
        let chipSecretShare = try verifyChipResponse(responseData: responseData)
        
        let (sessionEncKey, SessionMacKey, ssc) = try generateSessionKeys(chipSecretShare: chipSecretShare)
        
        print("[BAC] BAC thành công!")
        
        transceiver.secureMessaging = SecureMessaging(sessionEncKey: sessionEncKey, sessionMacKey: SessionMacKey, ssc: ssc)
    }
    
    // Giải mã response, verify chữ ký MAC và tách chipSecretShare từ chip CCCD.
    private func verifyChipResponse(responseData: [UInt8]) throws -> [UInt8] {
        print("[BAC] Giải mã và xác thực response từ chip")
        
        // Response chuẩn của BAC dài 40 bytes: 32 bytes đầu là chipAuthToken, 8 bytes cuối là chipAuthMAC
        guard responseData.count == 40 else {
            throw NFCReaderError.responseError("BAC thất bại: Chiều dài response không đúng 40 bytes.")
        }
        
        let chipAuthToken = Array(responseData[0..<32])
        let chipAuthMAC = Array(responseData[32..<40])
        
        // Verify MAC trước để đảm bảo tính toàn vẹn
        let calculatedChipAuthMAC = MAC(algoName: .DES, key: kmac, msg: pad(chipAuthToken, blockSize: 8))
        guard calculatedChipAuthMAC == chipAuthMAC else {
            throw NFCReaderError.responseError("BAC thất bại: Chữ ký MAC của chip không hợp lệ!")
        }
        
        // Giải mã chipAuthToken (32 bytes) bằng Kenc
        let iv: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let decrypted = tripleDESDecrypt(key: kenc, message: chipAuthToken, iv: iv)
        // decrypted = chipChallenge(8) + appChallenge(8) + chipSecretShare(16)

        let responseChipChallenge = Array(decrypted[0..<8])
        let responseAppChallenge = Array(decrypted[8..<16])
        let chipSecretShare = Array(decrypted[16..<32])

        // Verify appChallenge chip trả về phải khớp với appChallenge mobile gửi đi
        guard responseAppChallenge == appChallenge else {
            throw NFCReaderError.responseError("BAC thất bại: appChallenge không khớp! Chip có thể bị giả mạo.")
        }
        print("[BAC] Xác thực thành công. chipSecretShare = \(binToHexRep(chipSecretShare))")
        
        return chipSecretShare
    }

    // Dùng chipSecretShare sinh ra Session Keys cho bước đọc dữ liệu
    private func generateSessionKeys(chipSecretShare: [UInt8]) throws -> ([UInt8], [UInt8], [UInt8]) {
        print("[BAC] Sinh Session Keys")

        // KSeed = appSecretShare xor chipSecretShare
        let kSeed = xor(self.appSecretShare, chipSecretShare)
        print("[BAC] KSeed = \(binToHexRep(kSeed))")

        // Derive Session Keys (3DES)
        let keyGen = SessionKeyGenerator()
        let sessionEncKey = try keyGen.deriveKey(keySeed: kSeed, mode: .ENC_MODE)
        let SessionMacKey = try keyGen.deriveKey(keySeed: kSeed, mode: .MAC_MODE)
        print("[BAC] sessionEncKey = \(binToHexRep(sessionEncKey))")
        print("[BAC] SessionMacKey = \(binToHexRep(SessionMacKey))")

        // SSC (Send Sequence Counter) = 4 bytes cuối rnd.ICC + 4 bytes cuối rnd.IFD
        let ssc = Array(self.chipChallenge.suffix(4)) + Array(self.appChallenge.suffix(4))
        print("[BAC] SSC = \(binToHexRep(ssc))")
        
        return (sessionEncKey, SessionMacKey, ssc)
    }
    
    private func deriveKeySeed(from mrzKey: String) -> [UInt8] {
        let mrzByte = [UInt8](mrzKey.data(using: .utf8)!)
        
        let hash = calcSHA1Hash(mrzByte)
        
        // lấy 16 bytes đầu
        return Array(hash[0..<16])
    }
}
