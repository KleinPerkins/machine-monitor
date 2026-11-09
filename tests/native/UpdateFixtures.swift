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
    static var handler: ((URLRequest) -> (Int, Data, Int?))?
    static var afterDelivery: (() -> Void)?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.seen = request
        let (status, bytes, length) = Self.handler?(request) ?? (Self.status, Self.bytes, Self.contentLength)
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Length": String(length ?? bytes.count)])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: bytes)
        Self.afterDelivery?()
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@main struct UpdateFixtures {
    static func main() throws {
        if CommandLine.arguments.count > 1 && CommandLine.arguments[1] == "--update-recovery" {
            let request = try JSONSerialization.jsonObject(with: FileHandle.standardInput.readDataToEndOfFile()) as! [String: Any]
            let path = request["fixture_lock_path"] as! String
            var inherited = stat(), canonical = stat()
            guard fstat(3, &inherited) == 0, lstat(path, &canonical) == 0,
                  inherited.st_dev == canonical.st_dev, inherited.st_ino == canonical.st_ino,
                  inherited.st_mode & S_IFMT == S_IFREG, inherited.st_uid == getuid(),
                  inherited.st_mode & 0o777 == 0o600, inherited.st_nlink == 1 else { exit(3) }
            let retained = fcntl(3, F_DUPFD_CLOEXEC, 4)
            guard retained >= 4, flock(retained, LOCK_EX | LOCK_NB) == 0 else { exit(4) }
            close(3)
            if request["hold"] as? Bool == true { usleep(10_000_000) }
            close(retained)
            print("{\"ok\":true,\"lock_validated\":true}")
            return
        }
        if CommandLine.arguments.count > 2 && CommandLine.arguments[1] == "--closed-stderr-lock-probe" {
            close(STDERR_FILENO)
            try lockTransportFixtures(base: URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true))
            print("NATIVE_CLOSED_STDERR_LOCK passed")
            return
        }
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
        let admission = try UpdateRuntimeBinding.parse(["origin": origin.absoluteString, "channel": "qualification",
            "public_ed25519_key": key.publicKey.rawRepresentation.base64EncodedString(), "source_revision": String(repeating: "b", count: 40)])
        let target = try UpdateRuntimeBinding.parse(admission.dictionary.merging(["channel": "stable", "source_revision": manifest.source_revision]) { _, new in new })
        let bindingObject: [String: Any] = ["schema": "machine-monitor/runtime-bindings/v1", "admission": admission.dictionary, "target": target.dictionary]
        let bindings = try UpdateRuntimeBindings.parse(bindingObject)
        var qualifiedObject = object; qualifiedObject["channel"] = "qualification"; qualifiedObject["qualified"] = false
        let qualification = try UpdateManifest.parse(JSONSerialization.data(withJSONObject: qualifiedObject), configuration: bindings.admissionConfiguration(config))
        try bindings.validate(current: target, build: 2, oldBuild: 1, manifest: qualification)
        try bindings.validate(current: admission, build: 1, oldBuild: 1, manifest: qualification)
        try bindings.validate(current: target, build: 2, oldBuild: 1, manifest: qualification)
        try refuses("unrecorded runtime source") {
            let changed = try UpdateRuntimeBinding.parse(target.dictionary.merging(["source_revision": String(repeating: "c", count: 40)]) { _, new in new })
            try bindings.validate(current: changed, build: 2, oldBuild: 1, manifest: qualification)
        }
        for override in [["origin": "https://elsewhere.invalid"], ["public_ed25519_key": Data(repeating: 9, count: 32).base64EncodedString()]] {
            try refuses("runtime origin or publisher rotation") {
                _ = try UpdateRuntimeBindings.parse(["schema": "machine-monitor/runtime-bindings/v1", "admission": admission.dictionary,
                    "target": target.dictionary.merging(override) { _, new in new }])
            }
        }
        try refuses("stable to qualification runtime") {
            _ = try UpdateRuntimeBindings.parse(["schema": "machine-monitor/runtime-bindings/v1", "admission": target.dictionary, "target": admission.dictionary])
        }
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
        try check(FixtureProtocol.seen?.value(forHTTPHeaderField: "User-Agent") == "MachineMonitor-Update/1.0", "descriptive application client")
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
        try pieceFixtures(base: base, transport: transport, token: token, manifest: manifest)
        transport.close()
        let generations = UpdateGeneration(); let stale = generations.value; generations.invalidate()
        try check(!generations.accepts(stale), "remove/replacement invalidates late completions")
        try check(generations.accepts(generations.value), "current completion accepted")
        try stateFixtures(base: base, manifest: manifest)
        let disabled = UpdateCoordinator.bootstrap(bundle: .main)
        try check(disabled.phase == .disabled && disabled.allowsCollectorService && !disabled.suppressAutomaticScan, "fixture build update-disabled")
        print("NATIVE_UPDATE_FIXTURES " + String(assertions))
    }
    private static func pieceFixtures(base: URL, transport: UpdateTransport, token: String, manifest: UpdateManifest) throws {
        let size = UpdatePieceDescriptor.pieceSize
        let payload = Data((0..<(size + 13)).map { UInt8($0 % 251) })
        func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
        let archive = UpdateManifest.Archive(path: manifest.archive.path, size: payload.count, sha256: hash(payload), ed25519_signature: manifest.archive.ed25519_signature)
        let pieces = [payload.subdata(in: 0..<size), payload.subdata(in: size..<payload.count)]
        let rows: [[String: Any]] = pieces.enumerated().map { ["index": $0.offset, "size": $0.element.count, "sha256": hash($0.element)] }
        let descriptor: [String: Any] = ["schema": "machine-monitor/artifact-parts/v2", "app_id": UpdateConfiguration.appID,
            "release_id": "fixture", "kind": "archive", "artifact_sha256": archive.sha256, "artifact_size": archive.size, "part_size": size, "parts": rows]
        let json = try JSONSerialization.data(withJSONObject: descriptor)
        try check(try UpdatePieceDescriptor.parse(json, archive: archive).parts.count == 2, "bound piece descriptor")
        for change in [["part_size": true], ["part_size": size * 20], ["artifact_size": true], ["release_id": "other"], ["kind": "package"], ["parts": Array(rows.reversed())], ["parts": [rows[0], rows[0]]], ["parts": []], ["extra": 1]] as [[String: Any]] {
            try refuses("invalid piece descriptor") { _ = try UpdatePieceDescriptor.parse(JSONSerialization.data(withJSONObject: descriptor.merging(change) { _, new in new }), archive: archive) }
        }
        let duplicate = String(decoding: json, as: UTF8.self).replacingOccurrences(of: "\"part_size\":", with: "\"part_size\":1,\"part_size\":")
        try refuses("duplicate piece descriptor key") { _ = try UpdatePieceDescriptor.parse(Data(duplicate.utf8), archive: archive) }
        // Parse the full 512-MiB metadata boundary without allocating its payload.
        let maximum = UpdateManifest.Archive(path: archive.path, size: 512 * 1024 * 1024, sha256: archive.sha256, ed25519_signature: archive.ed25519_signature)
        let maximumRows: [[String: Any]] = (0..<2048).map { ["index": $0, "size": size, "sha256": archive.sha256] }
        let maximumTable = descriptor.merging(["artifact_size": maximum.size, "parts": maximumRows]) { _, new in new }
        let maximumJSON = try JSONSerialization.data(withJSONObject: maximumTable)
        try check(maximumJSON.count < UpdatePieceDescriptor.metadataLimit, "maximum descriptor fits wire bound")
        try check(try UpdatePieceDescriptor.parse(maximumJSON, archive: maximum).parts.last?.index == 2047, "maximum metadata and four-digit index")
        let padded = maximumJSON + Data(repeating: 32, count: UpdatePieceDescriptor.metadataLimit - maximumJSON.count)
        try check(try UpdatePieceDescriptor.parse(padded, archive: maximum).parts.count == 2048, "exact wire byte boundary")
        try refuses("wire bound plus one") { _ = try UpdatePieceDescriptor.parse(padded + Data([32]), archive: maximum) }
        for change in [["schema": "machine-monitor/artifact-parts/v1"], ["part_size": 1_048_576],
                       ["parts": maximumRows + [maximumRows[0]]],
                       ["parts": Array(maximumRows.dropLast()) + [maximumRows.last!.merging(["index": 2048]) { _, new in new }]]] as [[String: Any]] {
            try refuses("maximum descriptor overflow or legacy contract") { _ = try UpdatePieceDescriptor.parse(JSONSerialization.data(withJSONObject: maximumTable.merging(change) { _, new in new }), archive: maximum) }
        }
        var mode = "normal", requests = [String]()
        FixtureProtocol.handler = { request in
            let path = request.url!.path; requests.append(path)
            if path.hasSuffix("/parts") { return (200, json, nil) }
            let index = Int(path.split(separator: "/").last!)!
            if mode == "revoke" && index == 1 { return (401, Data(), nil) }
            if mode == "tamper" && index == 1 { return (200, Data(repeating: 0, count: 13), 13) }
            if mode == "short" && index == 1 { return (200, Data(repeating: 0, count: 12), 13) }
            return (200, pieces[index], nil)
        }
        defer { FixtureProtocol.handler = nil; FixtureProtocol.afterDelivery = nil }
        let target = base.appendingPathComponent("assembled.zip")
        let result: Result<Data, Error> = try awaitValue { transport.download(archive: archive, token: token, output: target, completion: $0) }
        _ = try result.get(); try check(try Data(contentsOf: target) == payload, "ordered authenticated assembly")
        try check(requests.count == 3, "one descriptor and two piece requests")
        for bad in ["revoke", "tamper", "short", "cancel"] {
            mode = bad; requests = []; let output = base.appendingPathComponent("piece-" + bad)
            if bad == "cancel" { FixtureProtocol.afterDelivery = { DispatchQueue.main.async { transport.cancel() } } }
            let denied: Result<Data, Error> = try awaitValue { transport.download(archive: archive, token: token, output: output, completion: $0) }
            try refuses("partial piece operation succeeded") { _ = try denied.get() }
            try check(!FileManager.default.fileExists(atPath: output.path), "owned partial removed")
            FixtureProtocol.afterDelivery = nil
        }
        mode = "normal"; requests = []
        var instant = Date()
        let timed = UpdateTransport(origin: URL(string: "https://updates.invalid")!, fixtureProtocols: [FixtureProtocol.self], now: { instant })
        FixtureProtocol.afterDelivery = { instant = instant.addingTimeInterval(301) }
        let expiredOutput = base.appendingPathComponent("piece-deadline")
        let expired: Result<Data, Error> = try awaitValue { timed.download(archive: archive, token: token, output: expiredOutput, completion: $0) }
        try refuses("overall deadline resets between requests") { _ = try expired.get() }
        try check(requests.count == 1 && !FileManager.default.fileExists(atPath: expiredOutput.path), "deadline stops before first piece and removes partial")
        FixtureProtocol.afterDelivery = nil; timed.close(); requests = []
        let exists: Result<Data, Error> = try awaitValue { transport.download(archive: archive, token: token, output: target, completion: $0) }
        try refuses("preexisting output overwritten") { _ = try exists.get() }
        try check(try Data(contentsOf: target) == payload && requests.isEmpty, "preexisting output preserved")
    }
    private static func stateFixtures(base: URL, manifest: UpdateManifest) throws {
        try lockTransportFixtures(base: base.appendingPathComponent("helper-lock"))
        try crossBootFixtures(base: base.appendingPathComponent("cross-boot"), manifest: manifest)
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
    private static func lockTransportFixtures(base: URL) throws {
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let state = try UpdateOperationState(target: base.appendingPathComponent("Fixture.app"), base: base.appendingPathComponent("state"), bootID: "fixture-boot")
        try state.acquire()
        let contender = try UpdateOperationState(target: state.target, base: base.appendingPathComponent("state"), bootID: "fixture-boot")
        let helper = UpdateHelper()
        let binary = URL(fileURLWithPath: CommandLine.arguments[0])
        let payload: [String: Any] = ["action": "prepare", "operation_lock_fd": 3,
            "fixture_lock_path": state.directory.appendingPathComponent("operation.lock").path]
        try refuses("recovery before helper launch") { try contender.acquire() }
        let result: Result<[String: Any], Error> = try awaitValue { done in
            helper.run(executable: binary, mode: "--update-recovery", payload: payload,
                       operationLock: try! state.preparationLock(), completion: done)
        }
        try check(try result.get()["lock_validated"] as? Bool == true, "helper inherited exact operation lock")
        try refuses("recovery after helper termination") { try contender.acquire() }
        var heldPayload = payload; heldPayload["hold"] = true
        let cancelled: Result<[String: Any], Error> = try awaitValue { done in
            helper.run(executable: binary, mode: "--update-recovery", payload: heldPayload,
                       operationLock: try! state.preparationLock(), completion: done)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { helper.cancel() }
        }
        if case .success = cancelled { throw UpdateFailure.invalid("cancelled helper succeeded") }
        try refuses("recovery after cancellation reaping") { try contender.acquire() }
        try check(try Data(contentsOf: state.directory.appendingPathComponent("operation.lock")).isEmpty, "lock contents unchanged")
        state.unlock(); try contender.acquire(); contender.unlock()
    }
    private static func crossBootFixtures(base: URL, manifest: UpdateManifest) throws {
        let oldBoot = "00000000-0000-4000-8000-000000000001", newBoot = "00000000-0000-4000-8000-000000000002"
        func setup(_ name: String, phase: String = "installer-pending", boot: String? = nil) throws -> UpdateOperationState {
            let directory = base.appendingPathComponent(name)
            let state = try UpdateOperationState(target: directory.appendingPathComponent("Fixture.app"), base: directory.appendingPathComponent("state"), bootID: newBoot)
            try state.acquire()
            let identity: [String: Any] = ["build": 1, "version": "1.0", "bundle_id": UpdateConfiguration.appID, "team_id": UpdateConfiguration.teamID, "data_schema_version": 1]
            let hash = String(repeating: "b", count: 64), transaction = String(repeating: "c", count: 32)
            var old = identity; old["sha256"] = hash
            try state.write("journal.json", ["schema": "machine-monitor/update-journal/v1", "transaction_id": transaction,
                "target_path": state.target.path, "boot_id": boot ?? oldBoot, "phase": phase, "old": old,
                "expected": manifest.dictionary, "credential_generation": 0,
                "backup": ["path": state.directory.appendingPathComponent("backups/" + transaction + ".app").path,
                    "identity": identity, "sha256": hash, "size": 100]])
            return state
        }
        let valid = try setup("valid")
        try check(try valid.reconcile(build: 2, verify: { try check($0 == 2, "cross-boot verifies expected build") }) == .ordinary && valid.needsAcceptance,
                  "verified explicit next-open adoption after reboot")
        try check(try valid.read("boot-adoption.json") != nil, "durable cross-boot intent precedes startup")
        try valid.acceptReadiness(build: 2)
        try check(try valid.read("boot-adoption.json") == nil, "accepted cross-boot intent resolved")
        try check(try valid.reconcile(build: 2, verify: { _ in }) == .ordinary, "subsequent accepted launch")
        valid.unlock()
        let interrupted = try setup("interrupted")
        _ = try interrupted.reconcile(build: 2, verify: { _ in }); interrupted.unlock()
        let restarted = try UpdateOperationState(target: interrupted.target, base: base.appendingPathComponent("interrupted/state"), bootID: newBoot)
        try refuses("interrupted cross-boot readiness") { _ = try restarted.reconcile(build: 2, verify: { _ in }) }; restarted.unlock()
        for name in ["marker", "preparation", "intent", "unverified", "wrong-build", "malformed-boot", "already-observed"] {
            let state = try setup(name, phase: name == "already-observed" ? "replacement-observed" : "installer-pending", boot: name == "malformed-boot" ? "invalid" : nil)
            if name == "marker" { try state.write("relaunch.json", ["unknown": true]) }
            if name == "preparation" { try state.write("preparation.json", ["unknown": true]) }
            if name == "intent" { try state.write("boot-adoption.json", ["unknown": true]) }
            try refuses("unsafe cross-boot " + name) {
                _ = try state.reconcile(build: name == "wrong-build" ? 1 : 2, verify: { _ in if name == "unverified" { throw UpdateFailure.recovery } })
            }
            state.unlock()
        }
    }
}
