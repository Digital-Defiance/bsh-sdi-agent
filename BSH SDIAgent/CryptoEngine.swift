import Foundation
import CryptoKit

/// Handles AES-256-GCM decryption of SDI payloads.
enum CryptoEngine {

    enum CryptoError: Error {
        case invalidKeyLength
        case invalidNonceLength
        case decryptionFailed
        case decodingFailed
    }

    /// Decrypts an SDI packet.
    ///
    /// - Parameters:
    ///   - sessionKey: 32-byte raw symmetric key.
    ///   - nonce: 12-byte GCM nonce.
    ///   - ciphertext: Encrypted payload bytes (ciphertext + appended 16-byte auth tag).
    ///   - additionalData: Additional Authenticated Data (AAD) — must match the AAD used during
    ///     encryption. Pass `Data()` (the default) if no AAD was used.
    /// - Returns: Decrypted plaintext `Data`.
    static func decrypt(
        sessionKey: Data,
        nonce nonceData: Data,
        ciphertext: Data,
        additionalData: Data = Data()
    ) throws -> Data {
        guard sessionKey.count == 32 else { throw CryptoError.invalidKeyLength }
        guard nonceData.count == 12 else { throw CryptoError.invalidNonceLength }

        let key = SymmetricKey(data: sessionKey)

        // CryptoKit expects ciphertext to include the auth tag appended at the end.
        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.SealedBox(combined: nonceData + ciphertext)
        } catch {
            throw CryptoError.decryptionFailed
        }

        do {
            return try AES.GCM.open(sealedBox, using: key, authenticating: additionalData)
        } catch {
            throw CryptoError.decryptionFailed
        }
    }

    /// Decrypts and deserializes a full SDI packet into an `SDIPayload`.
    static func decryptPayload(
        sessionKey: Data,
        nonce: Data,
        ciphertext: Data,
        additionalData: Data = Data()
    ) throws -> SDIPayload {
        let plaintext = try decrypt(sessionKey: sessionKey, nonce: nonce,
                                    ciphertext: ciphertext, additionalData: additionalData)
        do {
            return try JSONDecoder().decode(SDIPayload.self, from: plaintext)
        } catch {
            throw CryptoError.decodingFailed
        }
    }
}
