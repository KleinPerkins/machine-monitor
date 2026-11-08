import Foundation
import AppKit
import CryptoKit
import Darwin

private var assertions = 0
private func check(_ value: @autoclosure () throws -> Bool, _ message: String) throws {
    assertions += 1
    if try !value() { throw NSError(domain: "UpdateFixtures", code: assertions, userInfo: [NSLocalizedDescriptionKey: message]) }
}
private func refuses(_ message: String, _ block: () throws -> Void) throws {
    do { try block() } catch { assertions += 1; return }
    throw NSError(domain: "UpdateFixtures", code: 1, userInfo: [NSLocalizedDescriptionKey: "Accepted " + message])
}
private func awaitValue<T>(_ operation: (@escaping (T) -> Void) -> Void) throws -> T {
    var result: T?
    operation { result = $0 }
    let deadline = Date().addingTimeInterval(12)
    while result == nil && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.01)) }
    guard let result else { throw UpdateFailure.network }; return result
}
private final class FixtureProtocol: URLProtocol {
    static var status = 200
    static var bytes = Data("fixture".utf8)
    static var contentLength: Int? = nil
    static var seen: URLRequest?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.seen = request
        let response = HTTPURLResponse(url: request.url!, statusCode: Self.status, httpVersion: "HTTP/1.1", headerFields: ["Content-Length": String(Self.contentLength ?? Self.bytes.count)])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.bytes)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@main struct UpdateFixtures {
    static func main() throws {
        let base = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true).resolvingSymlinksInPath()
        let key = Curve25519.Signing.PrivateKey()
        let payload = Data(repeating: 0x5a, count: 180_001)
        let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        let signature = try key.signature(for: payload).base64EncodedString()
        let origin = URL(string: "https://updates.invalid")!
        let config = UpdateConfiguration(origin: origin, publicKey: key.publicKey.rawRepresentation, channel: "stable", currentBuild: 1, version: "1.0", bundle: .main)
        var object: [String: Any] = ["schema": "machine-monitor/release/v1", "app_id": UpdateConfiguration.appID,
            "bundle_id": UpdateConfiguration.appID, "team_id": UpdateConfiguration.teamID, "channel": "stable",
            "version": "1.1", "build": 2, "minimum_macos": "26.0", "architecture": "arm64", "data_schema_version": 1,
            "source_revision": String(repeating: "a", count: 40), "qualification_id": "fixture", "qualified": true,
            "archive": ["path": "/v1/apps/com.kleinperkins.machine-monitor/releases/fixture/archive", "size": payload.count, "sha256": digest, "ed25519_signature": signature],
            "first_install": ["path": "/v1/apps/com.kleinperkins.machine-monitor/releases/fixture/package", "size": payload.count, "sha256": digest, "ed25519_signature": signature]]
        func parse() throws -> UpdateManifest { try UpdateManifest.parse(JSONSerialization.data(withJSONObject: object), configuration: config) }
        let manifest = try parse()
        try refuses("duplicate root JSON key") { _ = try UpdateJSON.object(Data("{\"a\":1,\"a\":2}".utf8)) }
        try refuses("escaped duplicate nested key") { _ = try UpdateJSON.object(Data(#"{"outer":{"a":1,"\u0061":2}}"#.utf8)) }
        object["unexpected"] = true; try refuses("manifest extra field") { _ = try parse() }; object.removeValue(forKey: "unexpected")
        try check(manifest.build == 2, "valid release")
        for (field, bad) in [("team_id", "WRONG"), ("bundle_id", "other"), ("architecture", "x86_64"), ("minimum_macos", "27.0"), ("channel", "qualification")] {
            let original = object[field]; object[field] = bad
            try refuses(field) { _ = try parse() }; object[field] = original
        }
        object["qualified"] = false; try refuses("unqualified stable") { _ = try parse() }; object["qualified"] = true
        try refuses("origin escape") { _ = try config.endpoint("/v1/../evil") }
        try refuses("query credentials") { _ = try config.endpoint("/v1/access?token=x") }
        let token = Data(repeating: 0x61, count: 32).base64EncodedString().replacingOccurrences(of: "=", with: "")
        let accessObject: [String: Any] = ["schema": "machine-monitor/access/v1", "app_id": UpdateConfiguration.appID, "origin": origin.absoluteString, "token": token]
        let accessData = try JSONSerialization.data(withJSONObject: accessObject)
        _ = try UpdateAccess.parse(accessData, origin: origin)
        let accessPath = base.appendingPathComponent("fixture.machine-monitor-access")
        try accessData.write(to: accessPath)
        try check(try UpdateAccess.readFile(accessPath) == accessData, "bounded access file")
        let link = base.appendingPathComponent("access-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: accessPath)
        try refuses("symlink access file") { _ = try UpdateAccess.readFile(link) }
        let oversizedFile = base.appendingPathComponent("oversized-access")
        try Data(repeating: 65, count: 16_385).write(to: oversizedFile)
        try refuses("oversized access file") { _ = try UpdateAccess.readFile(oversizedFile) }
        try refuses("access origin") { _ = try UpdateAccess.parse(accessData, origin: URL(string: "https://other.invalid")!) }
        var badAccess = accessObject; badAccess["channel"] = "qualification"
        try refuses("access extra keys") { _ = try UpdateAccess.parse(JSONSerialization.data(withJSONObject: badAccess), origin: origin) }
        let archivePath = base.appendingPathComponent("archive.zip")
        try payload.write(to: archivePath); chmod(archivePath.path, 0o600)
        let archive = try UpdateVerifiedArchive(url: archivePath, manifest: manifest, key: key.publicKey.rawRepresentation)
        try check(try archive.read(offset: 70_000, count: 500) == payload.subdata(in: 70_000..<70_500), "descriptor read")
        try refuses("wrong signing key") { _ = try UpdateVerifiedArchive(url: archivePath, manifest: manifest, key: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation) }
        try refuses("unsigned fixture code") { try UpdateCodeVerifier.verify(base, expectedBuild: 2) }
        let bridge = UpdateLoopbackBridge(archive: archive, manifest: manifest)
        let feedResult: Result<URL, Error> = try awaitValue { bridge.start($0) }
        let feedURL = try feedResult.get()
        func fetch(_ url: URL) throws -> Data {
            let result: Result<Data, Error> = try awaitValue { done in
                URLSession.shared.dataTask(with: url) { data, _, error in
                    DispatchQueue.main.async { if let error { done(.failure(error)) } else { done(.success(data ?? Data())) } }
                }.resume()
            }
            return try result.get()
        }
        let feed = try fetch(feedURL)
        try check(String(decoding: feed, as: UTF8.self).contains(signature), "real signature in feed")
        try check(!String(decoding: feed, as: UTF8.self).contains(token), "feed excludes credential")
        let served = try fetch(feedURL.deletingLastPathComponent().appendingPathComponent("archive.zip"))
        try check(served == payload, "bridge serves descriptor bytes")
        let request = "GET /cap/appcast.xml HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n\r\n"
        try check(UpdateLoopbackBridge.parseRequest(Data(request.utf8), host: "127.0.0.1:1234", feedPath: "/cap/appcast.xml", archivePath: "/cap/archive.zip") != nil, "exact request")
        for bad in [request.replacingOccurrences(of: "127.0.0.1", with: "evil.invalid"), request.replacingOccurrences(of: "GET", with: "POST"), request.replacingOccurrences(of: "\r\n\r\n", with: "\r\nOrigin: https://evil.invalid\r\n\r\n"), request.replacingOccurrences(of: "\r\n\r\n", with: "\r\nHost: 127.0.0.1:1234\r\n\r\n")] {
            try check(UpdateLoopbackBridge.parseRequest(Data(bad.utf8), host: "127.0.0.1:1234", feedPath: "/cap/appcast.xml", archivePath: "/cap/archive.zip") == nil, "invalid bridge request")
        }
        bridge.stop()
        let replaced = base.appendingPathComponent("replaced.zip")
        try FileManager.default.moveItem(at: archivePath, to: replaced); try payload.write(to: archivePath); chmod(archivePath.path, 0o600)
        try refuses("path substitution") { try archive.verifyUnchanged() }
        let transport = UpdateTransport(origin: origin, fixtureProtocols: [FixtureProtocol.self])
        let received: Result<Data, Error> = try awaitValue { done in transport.request(url: origin.appendingPathComponent("v1/access/check"), token: token, limit: 100, completion: done) }
        try check(try received.get() == FixtureProtocol.bytes, "owned fixture session response")
        try check(FixtureProtocol.seen?.value(forHTTPHeaderField: "Authorization") == "Bearer " + token, "scoped authorization")
        try check(FixtureProtocol.seen?.value(forHTTPHeaderField: "Cookie") == nil, "no cookies")
        let denied: Result<Data, Error> = try awaitValue { done in transport.request(url: URL(string: "https://other.invalid/v1/access/check")!, token: token, limit: 100, completion: done) }
        try refuses("cross-origin request") { _ = try denied.get() }
        FixtureProtocol.status = 403
        let revoked: Result<Data, Error> = try awaitValue { done in transport.request(url: origin.appendingPathComponent("v1/access/check"), token: token, limit: 100, completion: done) }
        try refuses("revoked response") { _ = try revoked.get() }
        FixtureProtocol.status = 200; FixtureProtocol.contentLength = 101
        let oversized: Result<Data, Error> = try awaitValue { done in transport.request(url: origin.appendingPathComponent("v1/access/check"), token: token, limit: 100, completion: done) }
        try refuses("oversize response") { _ = try oversized.get() }
        var redirected = false
        transport.urlSession(URLSession.shared, task: URLSession.shared.dataTask(with: origin), willPerformHTTPRedirection: HTTPURLResponse(url: origin, statusCode: 302, httpVersion: nil, headerFields: nil)!, newRequest: URLRequest(url: URL(string: "https://other.invalid")!)) { redirected = $0 != nil }
        try check(!redirected, "all redirects refused")
        FixtureProtocol.contentLength = nil
        let downloadPath = base.appendingPathComponent("transport-download")
        let downloaded: Result<Data, Error> = try awaitValue { done in transport.request(url: origin.appendingPathComponent("v1/archive"), token: token, limit: 100, output: downloadPath, expectedSize: FixtureProtocol.bytes.count, completion: done) }
        _ = try downloaded.get()
        try check(try Data(contentsOf: downloadPath) == FixtureProtocol.bytes, "bounded streamed output")
        let permissions = try FileManager.default.attributesOfItem(atPath: downloadPath.path)[.posixPermissions] as? Int
        try check(permissions == 0o600, "private streamed file")
        let truncated: Result<Data, Error> = try awaitValue { done in transport.request(url: origin.appendingPathComponent("v1/archive"), token: token, limit: 100, expectedSize: 10, completion: done) }
        try refuses("wrong announced length") { _ = try truncated.get() }
        transport.close()
        let generations = UpdateGeneration(); let stale = generations.value; generations.invalidate()
        try check(!generations.accepts(stale), "remove/replacement invalidates late completions")
        try check(generations.accepts(generations.value), "current completion accepted")
        try stateFixtures(base: base, manifest: manifest)
        let disabled = UpdateCoordinator.bootstrap(bundle: .main)
        try check(disabled.phase == .disabled && disabled.allowsCollectorService && !disabled.suppressAutomaticScan, "fixture build update-disabled")
        print("NATIVE_UPDATE_FIXTURES " + String(assertions))
    }
    private static func stateFixtures(base: URL, manifest: UpdateManifest) throws {
        let target = base.appendingPathComponent("Fixture.app")
        let stateBase = base.appendingPathComponent("state")
        let state = try UpdateOperationState(target: target, base: stateBase, bootID: "fixture-boot")
        try state.acquire()
        let knownStage = try state.beginStaging(manifest: manifest)
        try Data("partial download".utf8).write(to: knownStage.appendingPathComponent("partial"))
        try state.cleanupStaging()
        try check(!FileManager.default.fileExists(atPath: knownStage.path), "known preinstaller crash staging cleaned")
        let foreign = base.appendingPathComponent("foreign")
        try FileManager.default.createDirectory(at: foreign, withIntermediateDirectories: false)
        try state.write("staging.json", ["schema": "machine-monitor/staging/v1", "target_path": target.path, "path": foreign.path, "identity": NSNull(), "build": 2, "sha256": manifest.archive.sha256])
        try refuses("foreign staging path") { try state.cleanupStaging() }
        try check(FileManager.default.fileExists(atPath: foreign.path), "foreign path preserved")
        try FileManager.default.removeItem(at: state.directory.appendingPathComponent("staging.json"))
        let pendingStage = try state.beginStaging(manifest: manifest)
        let contender = try UpdateOperationState(target: target, base: stateBase, bootID: "fixture-boot")
        try refuses("simultaneous recovery lock") { try contender.acquire() }
        let transaction = String(repeating: "a", count: 32)
        let old: [String: Any] = ["build": 1, "version": "1.0", "bundle_id": UpdateConfiguration.appID, "team_id": UpdateConfiguration.teamID, "data_schema_version": 1]
        let backupHash = String(repeating: "b", count: 64)
        let backup: [String: Any] = ["path": state.directory.appendingPathComponent("backups/" + transaction + ".app").path, "identity": old, "sha256": backupHash, "size": 100]
        var oldWithHash = old; oldWithHash["sha256"] = backupHash
        let journal: [String: Any] = ["schema": "machine-monitor/update-journal/v1", "target_path": target.path, "transaction_id": transaction,
            "boot_id": "fixture-boot", "phase": "installer-pending", "old": oldWithHash, "backup": backup, "expected": manifest.dictionary, "credential_generation": 0]
        try state.write("journal.json", journal)
        try state.cleanupStaging()
        try check(FileManager.default.fileExists(atPath: pendingStage.path), "pending installer staging preserved")
        try refuses("new staging over pending inventory") { _ = try state.beginStaging(manifest: manifest) }
        try refuses("unknown installer ownership") { _ = try state.reconcile(build: 1, verify: { _ in }) }
        let ordinary = try state.reconcile(build: 2, verify: { try check($0 == 2, "verify expected install") })
        try check(ordinary == .ordinary && state.needsAcceptance, "install-on-quit without marker")
        try state.acceptReadiness(build: 2)
        try state.cleanupStaging()
        try check(!FileManager.default.fileExists(atPath: pendingStage.path), "accepted replacement staging cleaned")
        try check(try state.read("acceptance.json")?["build"] as? Int == 2, "durable readiness receipt")
        try check(try state.reconcile(build: 2, verify: { _ in }) == .ordinary, "ordinary accepted launch")
        try state.write("journal.json", journal)
        _ = try state.reconcile(build: 2, verify: { _ in })
        try state.transition("installer-pending")
        try state.markActualRelaunch()
        try check(try state.reconcile(build: 2, verify: { _ in }) == .dormant, "actual relaunch dormant")
        try refuses("duplicate consumed marker") { _ = try state.reconcile(build: 2, verify: { _ in }) }
        try state.acceptReadiness(build: 2)
        try check(try state.reconcile(build: 2, verify: { _ in }) == .ordinary, "subsequent ordinary launch")
        try state.write("journal.json", journal)
        _ = try state.reconcile(build: 2, verify: { _ in }); try state.transition("installer-pending")
        try state.markActualRelaunch(now: Date().addingTimeInterval(-700))
        try refuses("stale marker") { _ = try state.reconcile(build: 2, verify: { _ in }) }
        state.unlock(); try contender.acquire(); contender.unlock()
    }
}
