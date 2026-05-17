import Foundation

/// Parses raw byte streams for OSC 7777 escape sequences.
///
/// Format (RFC §3.3, 7 fields):
///   ESC ] 7777 ; <session_id_hex> ; <b64counter> ; <type> ; <b64context> ;
///               <b64nonce> ; <b64ciphertext> ; <b64authtag> BEL
/// ESC = 0x1B, ] = 0x5D, BEL = 0x07
enum OSC7777Parser {

    struct ParsedPacket {
        let sessionID: String
        let counter: Data      // decoded from Base64, 8 bytes big-endian (RFC §3.5)
        let type: String       // plaintext type field (e.g. "ephemeral-auth")
        let context: String    // decoded routing context (e.g. API URL)
        let nonce: Data        // decoded from Base64
        let ciphertext: Data   // decoded ciphertext + auth tag (combined for CryptoKit)
    }

    enum ParseError: Error {
        case invalidFormat
        case base64DecodingFailed
        case missingFields
    }

    /// Scan raw data for OSC 7777 sequences and return all parsed packets found.
    static func scan(_ data: Data) -> [ParsedPacket] {
        // Convert to string for pattern matching; sequences use ASCII-safe Base64
        guard let raw = String(data: data, encoding: .utf8) else { return [] }
        return scan(raw)
    }

    static func scan(_ raw: String) -> [ParsedPacket] {
        var results: [ParsedPacket] = []
        // Match \e]7777;...\a  (ESC ] ... BEL)
        // Using regex for robust matching across multi-line buffers.
        let pattern = "\u{1B}\\]7777;([^\u{07}]+)\u{07}"
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(raw.startIndex..., in: raw)
        let matches = regex.matches(in: raw, range: range)

        for match in matches {
            guard let captureRange = Range(match.range(at: 1), in: raw) else { continue }
            let body = String(raw[captureRange])
            if let packet = try? parse(body: body) {
                results.append(packet)
            }
        }
        return results
    }

    /// Parse the semicolon-delimited body inside the OSC 7777 sequence.
    private static func parse(body: String) throws -> ParsedPacket {
        let parts = body.split(separator: ";", omittingEmptySubsequences: false)
        guard parts.count == 7 else { throw ParseError.missingFields }

        let sessionID  = String(parts[0])
        let b64Counter = String(parts[1])
        let typeStr    = String(parts[2])
        let b64Context = String(parts[3])
        let b64Nonce   = String(parts[4])
        let b64Cipher  = String(parts[5])
        let b64AuthTag = String(parts[6])

        guard
            let counterData = Data(base64Encoded: b64Counter),
            let nonce       = Data(base64Encoded: b64Nonce),
            let cipher      = Data(base64Encoded: b64Cipher),
            let authTag     = Data(base64Encoded: b64AuthTag)
        else {
            throw ParseError.base64DecodingFailed
        }

        guard counterData.count == 8 else { throw ParseError.invalidFormat }

        let contextData = Data(base64Encoded: b64Context) ?? Data()
        let context = String(data: contextData, encoding: .utf8) ?? ""

        // CryptoKit's AES.GCM.SealedBox(combined:) expects nonce+ciphertext+tag.
        // We pass nonce separately in CryptoEngine, so here we combine cipher+tag.
        let combined = cipher + authTag

        return ParsedPacket(sessionID: sessionID, counter: counterData, type: typeStr,
                            context: context, nonce: nonce, ciphertext: combined)
    }
}
