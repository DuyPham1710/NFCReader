//  Parse DG14, chứa "SecurityInfos", tức
//  danh sách các cơ chế bảo mật nâng cao mà chip hỗ trợ. Cấu trúc:
//
//    '6E' L
//        '31' L                          <- SET OF SecurityInfo
//            SecurityInfo (SEQUENCE)     <- có thể là ChipAuthenticationInfo
//            SecurityInfo (SEQUENCE)     <- hoặc ChipAuthenticationPublicKeyInfo
//            ...

import Foundation

public struct DG14 {
    public let chipAuthInfos: [ChipAuthenticationInfo]
    public let publicKeys: [ChipAuthenticationPublicKeyInfo]

    // OID prefix để phân biệt 2 loại SecurityInfo liên quan CA
    private static let publicKeyOIDPrefix = "0.4.0.127.0.7.2.2.1"
    private static let chipAuthOIDPrefix = "0.4.0.127.0.7.2.2.3"

    public init(data: [UInt8]) throws {
        // Bóc tag ngoài cùng (6E)
        var content = data
        if content.first == 0x6E {
            let root = try ASN1Node.parse(content)
            content = root.rawValue
        }

        // content giờ phải là nội dung của SET (tag 0x31) chứa các SecurityInfo
        let setNode = try ASN1Node.parse(content)
        guard setNode.tag == 0x31 else {
            throw NFCReaderError.responseError("DG14: thiếu tag 0x31 (SET OF SecurityInfo)")
        }

        var infos: [ChipAuthenticationInfo] = []
        var keys: [ChipAuthenticationPublicKeyInfo] = []

        for securityInfo in setNode.children {
            guard securityInfo.tag == 0x30, let firstChild = securityInfo.children.first, let oid = firstChild.oidString else { continue }

            if oid.hasPrefix(Self.chipAuthOIDPrefix) {
                // ChipAuthenticationInfo: SEQUENCE { OID, version INTEGER, keyId INTEGER OPTIONAL }
                guard securityInfo.children.count >= 2, let version = securityInfo.children[1].intValue else { continue }
                
                let keyId = securityInfo.children.count >= 3 ? securityInfo.children[2].intValue : nil
                infos.append(ChipAuthenticationInfo(protocolOID: oid, version: version, keyId: keyId))

            } else if oid.hasPrefix(Self.publicKeyOIDPrefix) {
                // ChipAuthenticationPublicKeyInfo: SEQUENCE { OID, SubjectPublicKeyInfo, keyId OPTIONAL }
                guard securityInfo.children.count >= 2 else { continue }
                
                let subjectPublicKeyInfo = securityInfo.children[1]
                
                guard subjectPublicKeyInfo.tag == 0x30, subjectPublicKeyInfo.children.count >= 2 else { continue }

                let algorithmIdentifier = subjectPublicKeyInfo.children[0]
                
                guard algorithmIdentifier.tag == 0x30, let algorithmOID = algorithmIdentifier.children.first?.oidString else {
                    continue
                }
                

                let publicKeyBitString = subjectPublicKeyInfo.children[1]
                guard let keyBytes = publicKeyBitString.bitStringContent else { continue }

                let keyId = securityInfo.children.count >= 3 ? securityInfo.children[2].intValue : nil

                keys.append(ChipAuthenticationPublicKeyInfo(
                    protocolOID: oid,
                    algorithmOID: algorithmOID,
                    publicKeyBytes: keyBytes,
                    subjectPublicKeyInfoBytes: subjectPublicKeyInfo.fullBytes,
                    keyId: keyId
                ))
            }
            // Các OID khác (PACEInfo, TerminalAuthenticationInfo...) - bỏ qua, ngoài phạm vi CA.
        }

        self.chipAuthInfos = infos
        self.publicKeys = keys
    }

    /// Tìm đúng public key khớp với 1 ChipAuthenticationInfo cụ thể (theo keyId).
    /// Nếu chip chỉ có duy nhất 1 public key và không khai báo keyId ở cả 2 phía,
    /// mặc định coi như chúng khớp nhau (trường hợp phổ biến nhất trên thực tế).
//    public func matchingPublicKey(for info: ChipAuthenticationInfo) -> ChipAuthenticationPublicKeyInfo? {
//        if let infoKeyId = info.keyId {
//            return publicKeys.first { $0.keyId == infoKeyId }
//        }
//        return publicKeys.count == 1 ? publicKeys.first : publicKeys.first { $0.keyId == nil }
//    }
}
