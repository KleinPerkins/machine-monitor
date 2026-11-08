import Foundation
import CryptoKit
import Security
import LocalAuthentication
import Darwin

enum UpdateFailure: Error, LocalizedError {
    case invalid(String), access, network, cancelled, recovery, busy
    var errorDescription: String? {
        switch self {
        case .invalid(let detail): return "Update verification failed: \(detail)."
        case .access: return "Access expired or revoked. Import a new access file to resume updates. Monitoring is still available."
        case .network: return "The update service is unavailable. Try again later."
        case .cancelled: return "Update cancelled."
        case .recovery: return "Installation needs recovery. Restart your Mac, then open Recovery before Machine Monitor."
        case .busy: return "Another update or recovery operation is in progress. Quit and reopen Machine Monitor."
        }
    }
}

struct UpdateConfiguration {
    static let appID = "com.kleinperkins.machine-monitor"
    static let teamID = "J2V7GRV5CM"
    let origin: URL
    let publicKey: Data
    let channel: String
    let currentBuild: Int
    let version: String
    let bundle: Bundle
    static func load(_ bundle: Bundle) -> UpdateConfiguration? {
        guard bundle.bundleIdentifier == appID,
              let originText = bundle.object(forInfoDictionaryKey: "MachineMonitorUpdateOrigin") as? String,
              let origin = URL(string: originText), validOrigin(origin), origin.absoluteString == originText,
              let keyText = bundle.object(forInfoDictionaryKey: "SUPublicEDKey") as? String,
              let key = Data(base64Encoded: keyText), key.count == 32,
              let channel = bundle.object(forInfoDictionaryKey: "MachineMonitorUpdateChannel") as? String,
              ["stable", "qualification"].contains(channel),
              let buildText = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
              let build = Int(buildText), build > 0,
              let version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
              bundle.object(forInfoDictionaryKey: "SUEnableAutomaticChecks") as? Bool == false,
              bundle.object(forInfoDictionaryKey: "SUAllowsAutomaticUpdates") as? Bool == true,
              bundle.object(forInfoDictionaryKey: "SUAutomaticallyUpdate") as? Bool == true,
              bundle.object(forInfoDictionaryKey: "SUVerifyUpdateBeforeExtraction") as? Bool == true,
              (try? UpdateCodeVerifier.verify(bundle.bundleURL, expectedBuild: build)) != nil
        else { return nil }
        return UpdateConfiguration(origin: origin, publicKey: key, channel: channel,
                                   currentBuild: build, version: version, bundle: bundle)
    }
    static func validOrigin(_ url: URL) -> Bool {
        url.scheme == "https" && url.host != nil && url.user == nil && url.password == nil &&
        url.query == nil && url.fragment == nil && url.path.isEmpty && (url.port == nil || url.port == 443)
    }
    func endpoint(_ path: String) throws -> URL {
        guard path.hasPrefix("/v1/"), !path.contains("%"), !path.contains(".."),
              !path.contains("?"), !path.contains("#"), !path.contains("\\"),
              let url = URL(string: origin.absoluteString + path),
              url.scheme == origin.scheme, url.host == origin.host, url.port == origin.port
        else { throw UpdateFailure.invalid("unapproved address") }
        return url
    }
}

struct UpdateAccess: Codable {
    let schema: String
    let app_id: String
    let origin: String
    let token: String
    static func readFile(_ url: URL) throws -> Data {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw UpdateFailure.invalid("access file") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size > 0,
              info.st_size <= 16_384, let data = try handle.read(upToCount: 16_385), data.count <= 16_384
        else { throw UpdateFailure.invalid("access file size") }
        return data
    }
    static func parse(_ data: Data, origin: URL) throws -> UpdateAccess {
        guard data.count <= 16_384, let object = try? UpdateJSON.object(data),
              Set(object.keys) == Set(["schema", "app_id", "origin", "token"]),
              let access = try? JSONDecoder().decode(UpdateAccess.self, from: data),
              access.schema == "machine-monitor/access/v1", access.app_id == UpdateConfiguration.appID,
              access.origin == origin.absoluteString, access.token.count == 43,
              access.token.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
              let decoded = Data(base64Encoded: access.token.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "="), decoded.count == 32,
              decoded.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == access.token
        else { throw UpdateFailure.invalid("invalid access file") }
        return access
    }
}

struct UpdateManifest: Codable, Equatable {
    struct Archive: Codable, Equatable { let path: String; let size: Int; let sha256: String; let ed25519_signature: String }
    let schema: String
    let app_id: String
    let bundle_id: String
    let team_id: String
    let channel: String
    let version: String
    let build: Int
    let minimum_macos: String
    let architecture: String
    let data_schema_version: Int
    let source_revision: String
    let qualification_id: String
    let qualified: Bool
    let archive: Archive
    let first_install: Archive
    static func parse(_ data: Data, configuration: UpdateConfiguration) throws -> UpdateManifest {
        guard data.count <= 65_536 else { throw UpdateFailure.invalid("oversized manifest") }
        guard let object = try? UpdateJSON.object(data),
              Set(object.keys) == Set(["schema", "app_id", "bundle_id", "team_id", "channel", "version", "build", "minimum_macos", "architecture", "data_schema_version", "source_revision", "qualification_id", "qualified", "archive", "first_install"]),
              let archiveObject = object["archive"] as? [String: Any], let packageObject = object["first_install"] as? [String: Any],
              Set(archiveObject.keys) == Set(["path", "size", "sha256", "ed25519_signature"]),
              Set(packageObject.keys) == Set(archiveObject.keys)
        else { throw UpdateFailure.invalid("manifest fields") }
        let m = try JSONDecoder().decode(Self.self, from: data)
        guard m.schema == "machine-monitor/release/v1", m.app_id == UpdateConfiguration.appID,
              m.bundle_id == UpdateConfiguration.appID, m.team_id == UpdateConfiguration.teamID,
              m.channel == configuration.channel, m.build > 0, m.build <= 9_007_199_254_740_991,
              m.minimum_macos == "26.0", m.architecture == "arm64", m.data_schema_version == 1,
              m.version.range(of: "^(0|[1-9][0-9]{0,8})(\\.(0|[1-9][0-9]{0,8})){0,3}$", options: .regularExpression) != nil,
              m.source_revision.range(of: "^[0-9a-f]{40}$", options: .regularExpression) != nil,
              m.qualification_id.range(of: "^[A-Za-z0-9_-]{1,128}$", options: .regularExpression) != nil,
              m.channel != "stable" || m.qualified,
              m.archive.size > 0, m.archive.size <= 512 * 1024 * 1024,
              m.archive.sha256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              Data(base64Encoded: m.archive.ed25519_signature)?.count == 64,
              m.archive.path.range(of: "^/v1/apps/com\\.kleinperkins\\.machine-monitor/releases/[A-Za-z0-9_-]{1,128}/archive$", options: .regularExpression) != nil
        else { throw UpdateFailure.invalid("incompatible release") }
        guard m.first_install.size > 0, m.first_install.size <= 512 * 1024 * 1024,
              m.first_install.sha256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              Data(base64Encoded: m.first_install.ed25519_signature)?.count == 64,
              m.first_install.path == String(m.archive.path.dropLast("archive".count)) + "package"
        else { throw UpdateFailure.invalid("first-install package") }
        guard Data(base64Encoded: m.archive.ed25519_signature)?.base64EncodedString() == m.archive.ed25519_signature,
              Data(base64Encoded: m.first_install.ed25519_signature)?.base64EncodedString() == m.first_install.ed25519_signature
        else { throw UpdateFailure.invalid("signature encoding") }
        _ = try configuration.endpoint(m.archive.path)
        return m
    }
    var dictionary: [String: Any] { (try? JSONSerialization.jsonObject(with: JSONEncoder().encode(self)) as? [String: Any]) ?? [:] }
}

// An open descriptor, never a later path lookup, is the source for cryptography and handoff.
final class UpdateVerifiedArchive {
    let fd: Int32
    let url: URL
    let size: Int
    private let identity: stat
    init(url: URL, manifest: UpdateManifest, key: Data) throws {
        self.url = url; size = manifest.archive.size
        fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw UpdateFailure.invalid("archive unavailable") }
        var value = stat()
        guard fstat(fd, &value) == 0, value.st_mode & S_IFMT == S_IFREG,
              value.st_uid == getuid(), value.st_nlink == 1, value.st_size == size,
              value.st_mode & 0o077 == 0 else { close(fd); throw UpdateFailure.invalid("archive identity") }
        identity = value
        // All stored properties are initialized: deinit owns the descriptor on throw.
        try verifyUnchanged()
        guard try sha256() == manifest.archive.sha256,
              let signature = Data(base64Encoded: manifest.archive.ed25519_signature)
        else { throw UpdateFailure.invalid("archive checksum") }
        let mapping = mmap(nil, size, PROT_READ, MAP_PRIVATE, fd, 0)
        guard let mapping, mapping != MAP_FAILED else { throw UpdateFailure.invalid("archive mapping") }
        defer { munmap(mapping, size) }
        let bytes = Data(bytesNoCopy: mapping, count: size, deallocator: .none)
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: key)
        guard publicKey.isValidSignature(signature, for: bytes) else { throw UpdateFailure.invalid("publisher signature") }
        try verifyUnchanged()
    }
    deinit { close(fd) }
    func verifyUnchanged() throws {
        var value = stat(), pathValue = stat()
        guard fstat(fd, &value) == 0, lstat(url.path, &pathValue) == 0,
              value.st_dev == identity.st_dev, value.st_ino == identity.st_ino,
              pathValue.st_dev == identity.st_dev, pathValue.st_ino == identity.st_ino,
              value.st_size == identity.st_size, value.st_mtimespec == identity.st_mtimespec,
              value.st_ctimespec == identity.st_ctimespec, value.st_nlink == 1
        else { throw UpdateFailure.invalid("archive changed") }
    }
    func sha256() throws -> String {
        var hash = SHA256(), offset = 0
        while offset < size {
            let data = try read(offset: offset, count: min(65_536, size - offset))
            hash.update(data: data); offset += data.count
        }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }
    func read(offset: Int, count: Int) throws -> Data {
        guard offset >= 0, count >= 0, offset <= size, count <= size - offset else { throw UpdateFailure.invalid("archive range") }
        var data = Data(count: count)
        let readCount = data.withUnsafeMutableBytes { pread(fd, $0.baseAddress, count, off_t(offset)) }
        guard readCount == count else { throw UpdateFailure.invalid("archive truncated") }
        return data
    }
}

extension timespec: @retroactive Equatable {
    public static func == (a: timespec, b: timespec) -> Bool { a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec }
}

enum UpdateCodeVerifier {
    static func verify(_ url: URL, expectedBuild: Int, expectedVersion: String? = nil) throws {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else { throw UpdateFailure.invalid("application signature") }
        let rule = "anchor apple generic and identifier \"\(UpdateConfiguration.appID)\" and certificate leaf[subject.OU] = \"\(UpdateConfiguration.teamID)\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(rule as CFString, [], &requirement) == errSecSuccess,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode), requirement) == errSecSuccess,
              let bundle = Bundle(url: url), bundle.bundleIdentifier == UpdateConfiguration.appID,
              let build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String, Int(build) == expectedBuild,
              expectedVersion == nil || bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String == expectedVersion,
              bundle.object(forInfoDictionaryKey: "LSMinimumSystemVersion") as? String == "26.0",
              bundle.object(forInfoDictionaryKey: "MachineMonitorDataSchemaVersion") as? Int == 1,
              let executable = bundle.executableURL,
              let handle = try? FileHandle(forReadingFrom: executable)
        else { throw UpdateFailure.invalid("application identity or platform") }
        defer { try? handle.close() }
        // Release payload is an arm64 thin Mach-O; fail closed for unqualified universal formats.
        guard let header = try handle.read(upToCount: 8), header.count == 8,
              Array(header.prefix(4)) == [0xcf, 0xfa, 0xed, 0xfe],
              Array(header.suffix(4)) == [0x0c, 0x00, 0x00, 0x01]
        else { throw UpdateFailure.invalid("application architecture") }
    }
}

protocol UpdateCredentialStore {
    func read() throws -> Data?
    func write(_ data: Data) throws
    func remove() throws
}
final class UpdateKeychainStore: UpdateCredentialStore {
    private let service: String
    init(target: URL) {
        service = UpdateConfiguration.appID + ".updates." + SHA256.hash(data: Data(target.path.utf8)).map { String(format: "%02x", $0) }.joined()
    }
    private var query: [String: Any] { [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service, kSecAttrAccount as String: "recipient", kSecAttrSynchronizable as String: false] }
    func read() throws -> Data? {
        var q = query; q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        let context = LAContext(); context.interactionNotAllowed = true
        q[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw UpdateFailure.invalid("Keychain access unavailable") }
        return result as? Data
    }
    func write(_ data: Data) throws {
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            guard SecItemAdd(query.merging(attributes) { _, b in b } as CFDictionary, nil) == errSecSuccess else { throw UpdateFailure.invalid("Keychain save failed") }
        } else if status != errSecSuccess { throw UpdateFailure.invalid("Keychain save failed") }
    }
    func remove() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw UpdateFailure.invalid("Keychain removal failed") }
    }
}

// All coordinator mutation and completion delivery occurs on the main queue.
final class UpdateGeneration {
    private(set) var value: UInt64 = 0
    @discardableResult func invalidate() -> UInt64 { value &+= 1; return value }
    func accepts(_ candidate: UInt64) -> Bool { candidate == value }
}
