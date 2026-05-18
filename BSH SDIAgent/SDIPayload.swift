import Foundation

/// Known SDI payload type identifiers (per RFC §4).
/// Stored as a plain `String` rather than an enum so the agent accepts custom
/// types defined by integrators without rejecting the OSC packet outright.
enum SDIPayloadType {
    static let ephemeralAuth = "ephemeral-auth"
    static let dbConnection  = "db-connection"
}

/// Top-level SDI payload — built by combining the OSC 7777 plaintext fields
/// (`type`, `context`) with the decrypted JSON body.
///
/// The encrypted JSON contains only the *flat* body — `ttl`, `issued_at`, and
/// the credential fields. `type` and `context` travel as plaintext OSC fields
/// (RFC §3.3) and are injected into the payload after decryption.
struct SDIPayload {
    let type: String
    let context: String
    let ttl: TimeInterval           // seconds
    let issuedAt: TimeInterval      // Unix seconds (RFC §4)
    let data: SDIPayloadData

    /// Decode the flat JSON plaintext that `bsh-inject` actually encrypts and
    /// combine it with the OSC-supplied `type` / `context` to form a full
    /// payload.
    static func decode(plaintext: Data, type: String, context: String) throws -> SDIPayload {
        let flat = try JSONDecoder().decode(SDIPlaintext.self, from: plaintext)
        return SDIPayload(
            type: type,
            context: context,
            ttl: flat.ttl ?? 300,
            issuedAt: flat.issuedAt ?? 0,
            data: SDIPayloadData(
                username: flat.username,
                password: flat.password,
                email: flat.email,
                additionalFields: flat.additionalFields,
                engine: flat.engine,
                host: flat.host,
                port: flat.port,
                user: flat.user,
                pass: flat.pass
            )
        )
    }
}

/// Internal flat JSON shape sent inside the AES-GCM ciphertext by `bsh-inject`.
private struct SDIPlaintext: Decodable {
    let ttl: TimeInterval?
    let issuedAt: TimeInterval?

    // ephemeral-auth fields
    let username: String?
    let password: String?
    let email: String?
    let additionalFields: [String: String]?

    // db-connection fields
    let engine: String?
    let host: String?
    let port: Int?
    let user: String?
    let pass: String?

    enum CodingKeys: String, CodingKey {
        case ttl
        case issuedAt = "issued_at"
        case username, password, email
        case additionalFields = "additional_fields"
        case engine, host, port, user, pass
    }
}

/// Union of known credential field shapes. Unknown keys are ignored.
struct SDIPayloadData {
    // ephemeral-auth fields
    let username: String?
    let password: String?
    let email: String?
    let additionalFields: [String: String]?

    // db-connection fields
    let engine: String?
    let host: String?
    let port: Int?
    let user: String?
    let pass: String?
}
