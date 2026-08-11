//  Luồng xử lý tổng quát:
//   1. App gọi readCard(mrzKey:completed:onError:) với MRZKey được tạo từ số CCCD, ngày sinh, ngày hết hạn (dùng để sinh khoá BAC/PACE).
//   2. NFCReader mở NFCTagReaderSession, chờ người dùng áp thẻ vào lưng iPhone.
//   3. Khi phát hiện thẻ (iso7816 tag) -> kết nối -> khởi tạo APDUTransceiver.
//   4. APDUTransceiver sẽ thực hiện PACE (ưu tiên) hoặc BAC để thiết lập kênh
//      Secure Messaging, sau đó đọc lần lượt các DataGroup (DG1, DG2, DG13, DG14...)
//      cùng COM & SOD để xác thực tính toàn vẹn dữ liệu.


import Foundation
@preconcurrency import CoreNFC
import Combine

@available(iOS 13, *)
public class NFCReader: NSObject, @unchecked Sendable {
 
    private var nfcSession: NFCTagReaderSession?
    private var transceiver: APDUTransceiver?

    private var mrzKey: MRZKey?
    private var dataGroupsToRead: [DataGroupId] = [.COM, .SOD, .DG1, .DG2, .DG13, .DG14]

    private var customMessageHandler: ((NFCViewDisplayMessage) -> String?)?
    private var completedReadingHandler: ((Result<NFCCardModel, NFCReaderError>) -> Void)?

    private let readerQueue = DispatchQueue(label: "com.nfcreader.session.queue")
    
    private var lastAlertMessage: String = ""
    
    private var pendingResult: Result<NFCCardModel, NFCReaderError>?
    
    public override init() {
      super.init()
    }
    
    
    public func readCard(
        mrzKey: MRZKey,
        customMessageHandler: ((NFCViewDisplayMessage) -> String?)? = nil,
        completed: @escaping (Result<NFCCardModel, NFCReaderError>) -> Void
    ) {
        guard NFCTagReaderSession.readingAvailable else {
            completed(.failure(.notSupported))
            return
        }
        
        self.mrzKey = mrzKey
        self.customMessageHandler = customMessageHandler
        self.completedReadingHandler = completed
        self.transceiver = nil
 
     //   let config = NFCTagReaderSession.Configuration(pollingOption: [.iso14443])
        
        self.nfcSession = NFCTagReaderSession(
         //   configuration: config,
            pollingOption: [.iso14443],
            delegate: self,
            queue: readerQueue
        )
       
        self.nfcSession?.alertMessage = NFCViewDisplayMessage
            .requestPresentCard
            .description(customMessageHandler: customMessageHandler)
        
        self.nfcSession?.begin()
        
    }
    
    public func stopReadCard() {
        nfcSession?.invalidate()
        nfcSession = nil
    }
 
    private func updateAlert(message: NFCViewDisplayMessage) {
        let newMessage = message.description(customMessageHandler: customMessageHandler)
        
        guard newMessage != lastAlertMessage else { return }
        lastAlertMessage = newMessage
        
        DispatchQueue.main.async { [weak self] in
            self?.nfcSession?.alertMessage = newMessage
            
        }
      //  nfcSession?.alertMessage = message.description(customMessageHandler: customMessageHandler)
    }
    
    private func finish(with result: Result<NFCCardModel, NFCReaderError>, invalidateMessage: String? = nil) {
        self.pendingResult = result
        
       switch result {
       case .success:
           nfcSession?.alertMessage = NFCViewDisplayMessage
               .successfulRead
               .description(customMessageHandler: self.customMessageHandler)
           nfcSession?.invalidate()
       case .failure(let err):
           nfcSession?.invalidate(errorMessage: invalidateMessage ?? err.localizedDescription)
       }
//       completedReadingHandler?(result)
//       completedReadingHandler = nil
   }
}



@available(iOS 13, *)
extension NFCReader: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        print("NFC Reader Session đã kích hoạt.")
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        self.nfcSession = nil
         
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { [weak self] in
            // Nếu đã có kết quả trả về rồi (thành công/thất bại) thì không cần báo lỗi lại.
            guard let self = self, let handler = self.completedReadingHandler else { return }
     
            if let result = self.pendingResult {
                handler(result)
                self.pendingResult = nil
                self.completedReadingHandler = nil
                return
            }
            
            if let coreNFCError = error as? CoreNFC.NFCReaderError {
                switch coreNFCError.code {
                case .readerSessionInvalidationErrorUserCanceled:
                    handler(.failure(.userCanceled))
                case .readerSessionInvalidationErrorSessionTimeout:
                    handler(.failure(.timeout))
                default:
                    handler(.failure(.unknown(coreNFCError)))
                }
            } else {
                handler(.failure(.unknown(error)))
            }
     
            self.completedReadingHandler = nil
        }
       
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard tags.count == 1, case let .iso7816(nativeTag) = tags[0] else {
          //  let retryMessage = "Phát hiện nhiều hơn 1 thẻ. Vui lòng chỉ để 1 thẻ CCCD gần iPhone!"
//            session.alertMessage = NFCViewDisplayMessage
//                .error(.moreThanOneTagFound)
//                .description(customMessageHandler: customMessageHandler)
//            
//            DispatchQueue.global().asyncAfter(deadline: .now() + 0.75) {
//                session.restartPolling()
//            }
            let errorMessage = NFCViewDisplayMessage
                            .error(.moreThanOneTagFound)
                            .description(customMessageHandler: customMessageHandler)
            
            self.finish(with: .failure(.moreThanOneTagFound), invalidateMessage: errorMessage)
            return
        }
 
        session.connect(to: tags[0]) { [weak self] (error: Error?) in
            guard let self = self else { return }
 
            if let error = error {
                self.finish(with: .failure(.connectionError), invalidateMessage: error.localizedDescription)
                return
            }
 
            guard let mrzKey = self.mrzKey else {
                self.finish(with: .failure(.invalidMRZKey))
                return
            }
 
            let transceiver = APDUTransceiver(tag: nativeTag)
            self.transceiver = transceiver
 
            self.updateAlert(message: .authenticatingWithCard(0))
 
            self.startReadingCard(transceiver: transceiver, mrzKey: mrzKey)
        }
    }
 
    
    private func startReadingCard(transceiver: APDUTransceiver, mrzKey: MRZKey) {
        Task {
            do {
                let bacHandler = BACHandler(transceiver: transceiver)
                try await bacHandler.performBACAndGetSessionKeys(mrzKey: mrzKey)
                
                var rawDataGroups: [DataGroupId: [UInt8]] = [:]
                
                // Đọc EF.COM
                let comRawData = try await self.readSecureFile(dgID: .COM, transceiver: transceiver)
                let com = try COM(data: comRawData)
                print("[NFCReader] COM - Các DataGroup có trong chip: \(com.dataGroupsPresent)")

                // Nếu có DG14 -> đọc DG14 -> thử Chip Authentication
                if com.dataGroupsPresent.contains(.DG14) {
                    let dg14RawData = try await readSecureFile(dgID: .DG14, transceiver: transceiver)
                    rawDataGroups[.DG14] = dg14RawData
                    let dg14 = try DG14(data: dg14RawData)

                    print("[NFCReader] Đã đọc DG14. Chip hỗ trợ \(dg14.chipAuthInfos.count) thuật toán CA, \(dg14.publicKeys.count) public key")
                                        
                    let caHandler = ChipAuthenticationHandler(dg14: dg14, transceiver: transceiver)
                    if caHandler.isSupported {
                        do {
                            try await caHandler.doChipAuthentication()
                        } catch {
                            print("[NFCReader] Lỗi Chip Authentication: \(error)")
                            print("[NFCReader] Fallback: Khôi phục lại phiên Secure Messaging gốc (BAC)")
                            // Nếu CA thất bại giữa chừng, Secure Messaging bị hỏng, ta phải làm lại BAC để khôi phục
                            try await bacHandler.performBACAndGetSessionKeys(mrzKey: mrzKey)
                        }
                    }
                }

        
                // Đọc DG1, DG2, DG13
                if let algo = transceiver.secureMessaging?.algoName {
                    print("[NFCReader] Chuẩn bị đọc thẻ bằng thuật toán Secure Messaging: \(algo == .AES ? "AES (Chip Authentication)" : "DES (BAC)")")
                }
                
                
                let dg1RawData = try await readSecureFile(dgID: .DG1, transceiver: transceiver)
                rawDataGroups[.DG1] = dg1RawData
                let dg1 = try DG1(data: dg1RawData)

                print("[NFCReader] Số CCCD: \(dg1.documentNumber)")
                print("     Họ: \(dg1.surname), Tên: \(dg1.givenNames)")
                print("     Ngày sinh: \(dg1.dateOfBirth), Giới tính: \(dg1.sex)")
                print("     Ngày hết hạn: \(dg1.dateOfExpiry), Quốc tịch: \(dg1.nationality)")
                
                
                let dg2RawData = try await readSecureFile(dgID: .DG2, transceiver: transceiver)
                rawDataGroups[.DG2] = dg2RawData
                let dg2 = try DG2(data: dg2RawData)
                print("[NFCReader] Đã đọc DG2 thành công. Kích thước ảnh: \(dg2.imageData.count) bytes")
                
                // Đọc DG13 (chứa thông tin riêng của thẻ CCCD Việt Nam)
                var dg13: DG13? = nil
                if com.dataGroupsPresent.contains(.DG13) {
                    let dg13RawData = try await readSecureFile(dgID: .DG13, transceiver: transceiver)
                    rawDataGroups[.DG13] = dg13RawData
                    print("[DG13] rawData: \(dg13RawData)")
                    dg13 = try DG13(data: dg13RawData)
                    print("[NFCReader] --- DG13 Dữ liệu tiếng Việt ---")
                    print("[NFCReader] Số CCCD: \(dg13?.documentNumber ?? "-")")
                    print("[NFCReader] Họ tên: \(dg13?.fullName ?? "-")")
                    print("[NFCReader] Ngày sinh: \(dg13?.dateOfBirth ?? "-")")
                    print("[NFCReader] Giới tính: \(dg13?.sex ?? "-")")
                    print("[NFCReader] Quốc tịch: \(dg13?.nationality ?? "-")")
                    print("[NFCReader] Dân tộc: \(dg13?.ethnicity ?? "-")")
                    print("[NFCReader] Tôn giáo: \(dg13?.religion ?? "-")")
                    print("[NFCReader] Quê quán: \(dg13?.hometown ?? "-")")
                    print("[NFCReader] Nơi thường trú: \(dg13?.permanentAddress ?? "-")")
                    print("[NFCReader] Đặc điểm nhận dạng: \(dg13?.personalCharacteristics ?? "-")")
                    print("[NFCReader] Ngày cấp: \(dg13?.dateOfIssue ?? "-")")
                    print("[NFCReader] Ngày hết hạn: \(dg13?.dateOfExpiry ?? "-")")
                    print("[NFCReader] Cha: \(dg13?.fatherName ?? "-"), Mẹ: \(dg13?.motherName ?? "-")")
                    print("[NFCReader] Chip ID: \(dg13?.chipId ?? "-")")
                    print("[NFCReader] -----------------------------")
                }
            
                // Đọc EF.SOD (dùng cho Passive Authentication)
                let sodRawData = try await readSecureFile(dgID: .SOD, transceiver: transceiver)
               
               // PASSIVE AUTHENTICATION
               let sod = try SOD(data: sodRawData)
               var paSuccess = false
                var sodSignatureValid = false
                                
                // Load masterList.pem từ Bundle (nếu app đã nhúng file này)
                var masterListPEM: String? = nil
//                if let pemURL = Bundle.main.url(forResource: "masterList", withExtension: "pem"),
//                   let pemData = try? String(contentsOf: pemURL, encoding: .utf8) {
//                    masterListPEM = pemData
//                    print("[NFCReader] Đã load masterList.pem (\(pemData.count) bytes)")
//                } else {
//                    print("[NFCReader] Không tìm thấy masterList.pem trong Bundle. Bỏ qua verify chữ ký SOD.")
//                }
                
                do {
                    let paResult = try PassiveAuthenticationHandler.performFullPA(
                        sodRawData: sodRawData,
                        sod: sod,
                        rawDataGroups: rawDataGroups,
                        masterListPEM: masterListPEM
                    )
                    paSuccess = paResult.dataIntegrityValid
                    sodSignatureValid = paResult.sodSignatureValid
               } catch {
                   print("[NFCReader] Passive Auth Thất bại: \(error)")
               }

               var model = NFCCardModel(dg1: dg1, dg13: dg13, dg2: dg2)
               model.passiveAuthSuccess = paSuccess
//                model.printFormattedText()
//                model.printFormattedJSON()
                
                self.finish(with: .success(model))
            } catch let error as NFCReaderError {
                self.finish(with: .failure(error))
            } catch {
                self.finish(with: .failure(.unknown(error)))
            }
        }
    }
    

    private func readSecureFile(dgID: DataGroupId, transceiver: APDUTransceiver) async throws -> [UInt8] {
        // SELECT FILE - build APDU thô, bọc qua protect(), gửi, rồi unprotect() response
        let selectResponse = try await transceiver.selectFile(fileId: dgID.fileId)
        guard selectResponse.isSuccess else {
            throw NFCReaderError.responseError("SELECT FILE thất bại, SW=\(selectResponse.statusWordHex)")
        }

        // READ BINARY - đọc 4 byte đầu để biết tổng độ dài file
        let headerResponse = try await transceiver.readBinary(offset: 0, length: 4)
        guard headerResponse.isSuccess else {
            throw NFCReaderError.responseError("READ BINARY (header) thất bại, SW=\(headerResponse.statusWordHex)")
        }
        

        let headerBytes = [UInt8](headerResponse.data)
        let lengthResult = try asn1Length(Array(headerBytes[1...])) // bỏ byte tag đầu
        let totalFileLength = 1 + lengthResult.offset + lengthResult.length

        // Nếu 4 byte đã đủ (file rất ngắn) thì dùng luôn, không thì đọc tiếp phần còn thiếu
        var fileData = headerBytes
        let maxChunkSize = 224
        
        while fileData.count < totalFileLength {
            let remaining = totalFileLength - fileData.count
            let chunkSize = min(remaining, maxChunkSize)
            
            let chunkResponse = try await transceiver.readBinary(offset: fileData.count, length: chunkSize)
            guard chunkResponse.isSuccess else {
                throw NFCReaderError.responseError("READ BINARY (phần còn lại) thất bại, SW=\(chunkResponse.statusWordHex)")
            }
            
            fileData += [UInt8](chunkResponse.data)
            
            // Cập nhật % tiến trình
            let progress = Int((Double(fileData.count) / Double(totalFileLength)) * 100)
            self.updateAlert(message: .readingDataGroupProgress(dgID, progress))
        }

        return fileData
    }
    
}
