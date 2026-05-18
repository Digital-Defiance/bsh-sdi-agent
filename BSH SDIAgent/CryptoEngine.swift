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

    /// Decrypts the ciphertext and combines the flat JSON plaintext with the
    /// `type` / `context` fields lifted from the OSC 7777 sequence to build a
    /// full `SDIPayload`. See `SDIPayload.decode(plaintext:type:context:)` for
    /// the schema rationale.
    static func decryptPayload(
        sessionKey: Data,
        nonce: Data,
        ciphertext: Data,
        additionalData: Data = Data(),
        type: String,
        context: String
    ) throws -> SDIPayload {
        let plaintext = try decrypt(sessionKey: sessionKey, nonce: nonce,
                                    ciphertext: ciphertext, additionalData: additionalData)
        do {
            return try SDIPayload.decode(plaintext: plaintext, type: type, context: context)
        } catch {
            throw CryptoError.decodingFailed
        }
    }
}
