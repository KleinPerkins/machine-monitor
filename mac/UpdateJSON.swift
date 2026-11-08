import Foundation

// Foundation's object decoder silently accepts duplicate keys. Reject them before decoding
// credentials, manifests or durable authority records, including escaped-key aliases.
enum UpdateJSON {
    static func object(_ data: Data, limit: Int = 262_144) throws -> [String: Any] {
        guard data.count <= limit else { throw UpdateFailure.invalid("JSON size") }
        var scanner = Scanner(bytes: Array(data)); try scanner.value(depth: 0); scanner.whitespace()
        guard scanner.index == scanner.bytes.count,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw UpdateFailure.invalid("JSON object") }
        return object
    }
    private struct Scanner {
        let bytes: [UInt8]
        var index = 0
        mutating func whitespace() { while index < bytes.count && [9, 10, 13, 32].contains(bytes[index]) { index += 1 } }
        mutating func take(_ byte: UInt8) -> Bool {
            whitespace(); guard index < bytes.count, bytes[index] == byte else { return false }; index += 1; return true
        }
        mutating func value(depth: Int) throws {
            whitespace(); guard depth < 24, index < bytes.count else { throw UpdateFailure.invalid("JSON nesting") }
            switch bytes[index] {
            case 123:
                index += 1; var keys = Set<String>()
                if take(125) { return }
                repeat {
                    whitespace(); let key = try string()
                    guard keys.insert(key).inserted, take(58) else { throw UpdateFailure.invalid("duplicate JSON key") }
                    try value(depth: depth + 1)
                    if take(125) { return }
                } while take(44)
                throw UpdateFailure.invalid("JSON object")
            case 91:
                index += 1; if take(93) { return }
                repeat { try value(depth: depth + 1); if take(93) { return } } while take(44)
                throw UpdateFailure.invalid("JSON array")
            case 34: _ = try string()
            default:
                let start = index
                while index < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[index]) { index += 1 }
                guard index > start else { throw UpdateFailure.invalid("JSON value") }
                let token = Data(bytes[start..<index])
                _ = try JSONSerialization.jsonObject(with: token, options: [.fragmentsAllowed])
            }
        }
        mutating func string() throws -> String {
            let start = index
            guard index < bytes.count, bytes[index] == 34 else { throw UpdateFailure.invalid("JSON key") }
            index += 1; var escaped = false
            while index < bytes.count {
                let byte = bytes[index]; index += 1
                if !escaped && byte == 34 {
                    guard let value = try JSONSerialization.jsonObject(with: Data(bytes[start..<index]), options: [.fragmentsAllowed]) as? String else { throw UpdateFailure.invalid("JSON string") }
                    return value
                }
                if byte < 32 { throw UpdateFailure.invalid("JSON control character") }
                if escaped { escaped = false } else if byte == 92 { escaped = true }
            }
            throw UpdateFailure.invalid("JSON string")
        }
    }
}
