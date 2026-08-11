// Trích xuất danh sách mã băm của các Data Group từ file EF.SOD.
//  Sử dụng cơ chế duyệt cây ASN.1 (DFS) để tìm kiếm tự động mà không cần OpenSSL.

import Foundation

public struct SOD {
    /// Bảng mapping từ DataGroupId sang mã Hash thực tế của DataGroup đó (chứa trong file SOD)
    public let dataGroupHashes: [DataGroupId: [UInt8]]
    
    /// Thuật toán băm (ví dụ SHA-256 = "2.16.840.1.101.3.4.2.1")
    public let hashAlgorithmOid: String
    
    private struct LDSSecurityObjectNodes {
        let hashAlgorithmOidNode: ASN1Node?
        let hashListNode: ASN1Node
    }
    
    public init(data: [UInt8]) throws {
        let root = try ASN1Node.parse(data)
        
        // Tìm node chứa thuật toán băm và danh sách Hash
        // Trong LDSSecurityObject, chúng ta sẽ tìm 1 SEQUENCE chứa list các SEQUENCE con (mỗi SEQUENCE con gồm 1 INTEGER và 1 OCTET STRING)
        
        guard let ldsInfo = SOD.findLDSSecurityObject(in: root) else {
            throw NFCReaderError.responseError("SOD: Không tìm thấy danh sách Hash của DataGroup")
        }
        
        var hashes: [DataGroupId: [UInt8]] = [:]
        
        // Phân tích các DataGroupHash
        for child in ldsInfo.hashListNode.children where child.tag == 0x30 {
            guard child.children.count == 2,
                  child.children[0].tag == 0x02, // INTEGER (dataGroupNumber)
                  child.children[1].tag == 0x04  // OCTET STRING (dataGroupHashValue)
            else { continue }
 
            let dgNumberBytes = child.children[0].rawValue
            guard let dgNumber = SOD.readInt(from: dgNumberBytes) else { continue }
 
            let hashBytes = child.children[1].rawValue
 
            // Map number to DataGroupId
            if let dgId = SOD.mapToDataGroupId(dgNumber) {
                hashes[dgId] = hashBytes
            }
        }
 
        self.dataGroupHashes = hashes
        self.hashAlgorithmOid = ldsInfo.hashAlgorithmOidNode?.oidString ?? "UNKNOWN"
         
        guard !self.dataGroupHashes.isEmpty else {
            throw NFCReaderError.responseError("SOD: Danh sách Hash bị rỗng")
        }
    }

    
    /// Tìm LDSSecurityObject bằng đệ quy (DFS).
    /// Dấu hiệu nhận biết: 1 SEQUENCE mà PHẦN TỬ CUỐI là 1 SEQUENCE khác, trong đó
    /// mọi con của nó đều là SEQUENCE{INTEGER, OCTET STRING} (= dataGroupHashValues).
    /// Phần tử ngay TRƯỚC nó (children[count-2]) chính là hashAlgorithm (AlgorithmIdentifier),
    /// lấy OID từ node con đầu tiên của nó.
    private static func findLDSSecurityObject(in node: ASN1Node) -> LDSSecurityObjectNodes? {
        if node.tag == 0x30, node.children.count >= 2,
           let hashListCandidate = node.children.last,
           hashListCandidate.tag == 0x30,
           !hashListCandidate.children.isEmpty,
           hashListCandidate.children.allSatisfy({ child in
               child.tag == 0x30 &&
               child.children.count == 2 &&
               child.children[0].tag == 0x02 &&
               child.children[1].tag == 0x04
           }) {
            // hashAlgorithm là phần tử ngay trước dataGroupHashValues trong SEQUENCE
            let algorithmIdentifierNode = node.children[node.children.count - 2]
            let oidNode = algorithmIdentifierNode.children.first(where: { $0.tag == 0x06 })
            return LDSSecurityObjectNodes(hashAlgorithmOidNode: oidNode, hashListNode: hashListCandidate)
        }
        
        for child in node.children {
            if let found = findLDSSecurityObject(in: child) {
                return found
            }
        }
        
        // ĐẶC BIỆT: Trong chuẩn PKCS#7 (SOD), LDSSecurityObject thường bị "bọc"
        // dưới dạng mảng byte thô (primitive) bên trong OCTET STRING (0x04)
        // hoặc Context-Specific [0] (0xA0).
        // Thử parse rawValue của nó thành cây ASN1 con và tiếp tục tìm kiếm.
        if node.tag == 0x04 || node.tag == 0xA0 {
          if let innerNode = try? ASN1Node.parse(node.rawValue) {
              if let found = findLDSSecurityObject(in: innerNode) {
                  return found
              }
          }
        }

        return nil
    }
    
    private static func readInt(from bytes: [UInt8]) -> Int? {
        guard !bytes.isEmpty else { return nil }
        var value = 0
        for byte in bytes {
            value = (value << 8) | Int(byte)
        }
        return value
    }
    
    private static func mapToDataGroupId(_ number: Int) -> DataGroupId? {
        switch number {
        case 1: return .DG1
        case 2: return .DG2
        case 13: return .DG13
        case 14: return .DG14
        default: return nil
        }
    }
}
