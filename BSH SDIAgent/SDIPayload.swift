import Foundation

/// Supported SDI payload types per the RFC.
enum SDIPayloadType: String, Codable {
    case ephemeralAuth = "ephemeral-auth"
    case dbConnection  = "db-connection"
}

/// Top-level SDI payload envelope.
struct SDIPayload: Codable {
    let type: SDIPayloadType
    let context: String
    let ttl: TimeInterval           // seconds
    let data: SDIPayloadData
}

/// Union of known data shapes. Unknown keys are ignored.
struct SDIPayloadData: Codable {
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
        case username, password, email
        case additionalFields = "additional_fields"
        case engine, host, port, user, pass
    }
}
