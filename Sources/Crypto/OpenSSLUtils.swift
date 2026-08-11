import Foundation
import OpenSSL

@available(iOS 13, macOS 10.15, *)
public class OpenSSLUtils {
    
    /// Trả về mô tả lỗi từ OpenSSL
    public static func getOpenSSLError() -> String {
        guard let out = BIO_new(BIO_s_mem()) else { return "Unknown" }
        defer { BIO_free(out) }
        
        ERR_print_errors(out)
        let str = OpenSSLUtils.bioToString(bio: out)
        return str
    }
    
    /// Trích xuất nội dung text từ BIO pointer
    static func bioToString(bio: OpaquePointer) -> String {
        let len = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
        var buffer = [CChar](repeating: 0, count: len + 1)
        BIO_read(bio, &buffer, Int32(len))
        
        // Ensure null terminated
        buffer[len] = 0
        return String(cString: buffer)
    }

    /// Lấy mảng byte (thô) của khoá Public Key từ con trỏ EVP_PKEY
    public static func getPublicKeyData(from key: OpaquePointer) -> [UInt8]? {
        var data: [UInt8] = []
        let v = EVP_PKEY_get_base_id(key)
        
        if v == EVP_PKEY_DH || v == EVP_PKEY_DHX {
            guard let dh = EVP_PKEY_get0_DH(key) else {
                return nil
            }
            var dhPubKey: OpaquePointer?
            DH_get0_key(dh, &dhPubKey, nil)
            
            let nrBytes = (BN_num_bits(dhPubKey) + 7) / 8
            data = [UInt8](repeating: 0, count: Int(nrBytes))
            _ = BN_bn2bin(dhPubKey, &data)
            
        } else if v == EVP_PKEY_EC {
            guard let ec = EVP_PKEY_get0_EC_KEY(key),
                  let ec_pub = EC_KEY_get0_public_key(ec),
                  let ec_group = EC_KEY_get0_group(ec) else {
                return nil
            }
            
            let form = EC_KEY_get_conv_form(ec)
            let len = EC_POINT_point2oct(ec_group, ec_pub, form, nil, 0, nil)
            data = [UInt8](repeating: 0, count: Int(len))
            if len == 0 {
                return nil
            }
            _ = EC_POINT_point2oct(ec_group, ec_pub, form, &data, len, nil)
        }
        
        return data.isEmpty ? nil : data
    }

    /// Tính toán Shared Secret bằng Diffie-Hellman (EC hoặc DH thường) giữa khoá private (mobile) và public (chip)
    public static func computeSharedSecret(privateKeyPair: OpaquePointer, publicKey: OpaquePointer) -> [UInt8] {
        var secret: [UInt8] = []
        let keyType = EVP_PKEY_get_base_id(privateKeyPair)
        
        if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
            let dh = EVP_PKEY_get1_DH(privateKeyPair)
            let dh_pub = EVP_PKEY_get1_DH(publicKey)
            
            var bn = BN_new()
            DH_get0_key(dh_pub, &bn, nil)
            
            secret = [UInt8](repeating: 0, count: Int(DH_size(dh)))
            let len = DH_compute_key(&secret, bn, dh)
            
            if len <= 0 {
                print("[OpenSSL] Lỗi DH compute_key: \(getOpenSSLError())")
            } else {
                secret = Array(secret[0..<Int(len)])
            }
            
            DH_free(dh)
            DH_free(dh_pub)
            
        } else {
            let ctx = EVP_PKEY_CTX_new(privateKeyPair, nil)
            defer { EVP_PKEY_CTX_free(ctx) }
            
            if EVP_PKEY_derive_init(ctx) != 1 {
                print("[OpenSSL] EVP_PKEY_derive_init ERROR: \(getOpenSSLError())")
            }
            
            if EVP_PKEY_derive_set_peer(ctx, publicKey) != 1 {
                print("[OpenSSL] EVP_PKEY_derive_set_peer ERROR: \(getOpenSSLError())")
            }
            
            var keyLen = 0
            if EVP_PKEY_derive(ctx, nil, &keyLen) != 1 {
                print("[OpenSSL] EVP_PKEY_derive (length) ERROR: \(getOpenSSLError())")
            }
            
            secret = [UInt8](repeating: 0, count: keyLen)
            if EVP_PKEY_derive(ctx, &secret, &keyLen) != 1 {
                print("[OpenSSL] EVP_PKEY_derive ERROR: \(getOpenSSLError())")
            }
        }
        
        return secret
    }
}
