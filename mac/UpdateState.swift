import Foundation
import CryptoKit
import Darwin

enum UpdateStartupDisposition { case ordinary, dormant, recovery, locked }

final class UpdateOperationState {
    let directory: URL
    let target: URL
    let bootID: String
    private var descriptor: Int32 = -1
    private(set) var journal: [String: Any]?
    private(set) var needsAcceptance = false
    private(set) var disposition: UpdateStartupDisposition = .ordinary
    init(target: URL, base: URL, bootID: String) throws {
        self.target = target.resolvingSymlinksInPath().standardizedFileURL; self.bootID = bootID
        let namespace = SHA256.hash(data: Data(self.target.path.utf8)).map { String(format: "%02x", $0) }.joined()
        directory = base.appendingPathComponent(namespace, isDirectory: true)
        try Self.privateDirectory(base); try Self.privateDirectory(directory)
    }
    deinit { unlock() }
    static func privateDirectory(_ url: URL) throws {
        let fm = FileManager.default
        if !fm.fileExists(atPath: url.path) { try fm.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
        var info = stat()
        guard lstat(url.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0,
              url.standardizedFileURL.path == url.resolvingSymlinksInPath().standardizedFileURL.path
        else { throw UpdateFailure.invalid("unsafe update state directory") }
    }
    func acquire() throws {
        if descriptor >= 0 { return }
        let fd = open(directory.appendingPathComponent("operation.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        var info = stat()
        guard fd >= 0, fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
              info.st_nlink == 1, info.st_mode & 0o077 == 0 else { if fd >= 0 { close(fd) }; throw UpdateFailure.invalid("operation lock") }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { close(fd); throw UpdateFailure.busy }
        descriptor = fd
    }
    // Close this reference only; an inherited preparation reference must keep
    // its shared open-file-description lock if the parent exits first.
    func unlock() { if descriptor >= 0 { close(descriptor); descriptor = -1 } }
    func preparationLock() throws -> FileHandle {
        precondition(descriptor >= 0)
        // Always differ from the stdio destination: dup2 then clears CLOEXEC
        // even when the original app was launched with stderr closed.
        let fd = fcntl(descriptor, F_DUPFD_CLOEXEC, 4)
        guard fd >= 4 else { throw UpdateFailure.invalid("preparation lock") }
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }
    func read(_ name: String) throws -> [String: Any]? {
        precondition(descriptor >= 0)
        let path = directory.appendingPathComponent(name).path
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 && errno == ENOENT { return nil }
        guard fd >= 0 else { throw UpdateFailure.invalid("state read") }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(),
              info.st_nlink == 1, info.st_mode & 0o077 == 0, info.st_size > 0, info.st_size <= 262_144
        else { throw UpdateFailure.invalid("state identity") }
        var data = Data(count: Int(info.st_size))
        guard data.withUnsafeMutableBytes({ Darwin.read(fd, $0.baseAddress, $0.count) }) == data.count,
              let result = try? UpdateJSON.object(data)
        else { throw UpdateFailure.invalid("state format") }
        return result
    }
    func write(_ name: String, _ object: [String: Any]) throws {
        precondition(descriptor >= 0)
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let temporary = directory.appendingPathComponent(".write-" + UUID().uuidString)
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw UpdateFailure.invalid("state write") }
        defer { close(fd); unlink(temporary.path) }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }
            guard count > 0 else { throw UpdateFailure.invalid("state write") }; offset += count
        }
        guard fsync(fd) == 0, rename(temporary.path, directory.appendingPathComponent(name).path) == 0 else { throw UpdateFailure.invalid("state persistence") }
        try syncDirectory()
    }
    private func syncDirectory() throws {
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw UpdateFailure.invalid("state directory") }; defer { close(fd) }
        guard fsync(fd) == 0 else { throw UpdateFailure.invalid("state persistence") }
    }
    func beginStaging(manifest: UpdateManifest) throws -> URL {
        precondition(descriptor >= 0)
        try cleanupStaging()
        guard try read("staging.json") == nil else { throw UpdateFailure.recovery }
        let path = directory.appendingPathComponent("staging-" + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(), isDirectory: true)
        var record: [String: Any] = ["schema": "machine-monitor/staging/v1", "target_path": target.path,
            "path": path.path, "identity": NSNull(), "build": manifest.build, "sha256": manifest.archive.sha256]
        // Durable intent precedes creation. No payload is written until inode identity is durable.
        try write("staging.json", record)
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var info = stat()
        guard lstat(path.path, &info) == 0 else { throw UpdateFailure.invalid("staging identity") }
        record["identity"] = ["device": UInt64(info.st_dev), "inode": UInt64(info.st_ino)]
        try write("staging.json", record)
        return path
    }
    func cleanupStaging() throws {
        precondition(descriptor >= 0)
        guard let record = try read("staging.json") else { return }
        let liveJournal = try read("journal.json")
        guard liveJournal == nil || ["prepared", "cancelled", "accepted", "restored"].contains(liveJournal?["phase"] as? String ?? "") else { return }
        if let restore = try read("recovery.json"), !["accepted", "rolled-back"].contains(restore["phase"] as? String ?? "") { return }
        guard record["schema"] as? String == "machine-monitor/staging/v1", record["target_path"] as? String == target.path,
              let pathString = record["path"] as? String,
              let build = record["build"] as? Int, build > 0,
              let digest = record["sha256"] as? String, digest.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
        else { throw UpdateFailure.invalid("staging record") }
        let path = URL(fileURLWithPath: pathString)
        guard path.lastPathComponent.range(of: "^staging-[0-9a-f]{32}$", options: .regularExpression) != nil,
              path.deletingLastPathComponent().path == directory.path,
              path.path == path.standardizedFileURL.path else { throw UpdateFailure.invalid("staging path") }
        var info = stat()
        if lstat(path.path, &info) == 0 {
            guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { throw UpdateFailure.invalid("staging ownership") }
            if let identity = record["identity"] as? [String: Any] {
                guard identity["device"] as? UInt64 == UInt64(info.st_dev), identity["inode"] as? UInt64 == UInt64(info.st_ino) else { throw UpdateFailure.invalid("staging identity changed") }
            } else {
                // A crash between mkdir and identity persistence cannot have written payload.
                guard record["identity"] is NSNull, try FileManager.default.contentsOfDirectory(atPath: path.path).isEmpty else { throw UpdateFailure.invalid("unidentified staging payload") }
            }
            try FileManager.default.removeItem(at: path)
        } else if errno != ENOENT { throw UpdateFailure.invalid("staging unavailable") }
        guard unlink(directory.appendingPathComponent("staging.json").path) == 0 else { throw UpdateFailure.invalid("staging record removal") }
        try syncDirectory()
    }
    func reconcile(build: Int, verify: (Int) throws -> Void, now: Date = Date()) throws -> UpdateStartupDisposition {
        try acquire()
        journal = try read("journal.json")
        let marker = try read("relaunch.json")
        // Consume by atomic rename before dashboard startup. A crash after consumption fails closed.
        if marker != nil {
            guard try read("relaunch-consumed.json") == nil,
                  rename(directory.appendingPathComponent("relaunch.json").path, directory.appendingPathComponent("relaunch-consumed.json").path) == 0
            else { throw UpdateFailure.recovery }
            try syncDirectory()
        }
        guard let j = journal else {
            guard marker == nil, try read("relaunch-consumed.json") == nil, try read("recovery.json") == nil else { throw UpdateFailure.recovery }
            disposition = .ordinary; return disposition
        }
        guard j["schema"] as? String == "machine-monitor/update-journal/v1", j["target_path"] as? String == target.path,
              let transaction = j["transaction_id"] as? String, transaction.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
              let phase = j["phase"] as? String, let expected = j["expected"] as? [String: Any],
              let expectedBuild = expected["build"] as? Int, let old = j["old"] as? [String: Any],
              let oldBuild = old["build"] as? Int, expectedBuild > oldBuild
        else { throw UpdateFailure.recovery }
        guard let backup = j["backup"] as? [String: Any],
              Set(backup.keys) == Set(["path", "sha256", "identity", "size"]),
              backup["path"] as? String == directory.appendingPathComponent("backups/" + transaction + ".app").path,
              let backupHash = backup["sha256"] as? String,
              backupHash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              let backupIdentity = backup["identity"] as? [String: Any],
              old["sha256"] as? String == backupHash,
              let backupSize = backup["size"] as? Int, backupSize >= 0,
              ["build", "version", "bundle_id", "team_id", "data_schema_version"].allSatisfy({ key in
                  guard let a = old[key] as? NSObject, let b = backupIdentity[key] as? NSObject else { return false }
                  return a == b
              }),
              backupIdentity["bundle_id"] as? String == UpdateConfiguration.appID,
              backupIdentity["team_id"] as? String == UpdateConfiguration.teamID,
              backupIdentity["data_schema_version"] as? Int == 1,
              oldBuild > 0, expectedBuild <= 9_007_199_254_740_991
        else { throw UpdateFailure.recovery }
        // Any unfinished restoration must be reconciled by the independent Recovery app.
        if let recovery = try read("recovery.json"), !["accepted", "rolled-back"].contains(recovery["phase"] as? String ?? "") { throw UpdateFailure.recovery }
        if phase == "restored" {
            guard marker == nil, let receipt = try read("recovery-receipt.json"),
                  receipt["transaction_id"] as? String == transaction,
                  receipt["target_path"] as? String == target.path,
                  receipt["build"] as? Int == oldBuild,
                  let backup = j["backup"] as? [String: Any],
                  receipt["sha256"] as? String == backup["sha256"] as? String,
                  build == oldBuild else { throw UpdateFailure.recovery }
            try verify(oldBuild); disposition = .ordinary; return disposition
        }
        if ["prepared", "cancelled"].contains(phase) {
            guard marker == nil, build == oldBuild else { throw UpdateFailure.recovery }
            try verify(build); disposition = .ordinary; return disposition
        }
        if phase == "accepted" {
            guard marker == nil, try read("relaunch-consumed.json") == nil,
                  let receipt = try read("acceptance.json"), receipt["transaction_id"] as? String == transaction,
                  receipt["target_path"] as? String == target.path, receipt["build"] as? Int == expectedBuild,
                  build == expectedBuild else { throw UpdateFailure.recovery }
            try verify(build); try cleanupBootAdoption(transaction: transaction, build: build)
            disposition = .ordinary; return disposition
        }
        if phase == "installer-pending", let previousBoot = j["boot_id"] as? String, previousBoot != bootID {
            // This is a separate explicit-next-open path, not an updater marker
            // exception. A changed OS boot proves old-boot installers have ended.
            guard UUID(uuidString: previousBoot)?.uuidString.lowercased() == previousBoot,
                  UUID(uuidString: bootID)?.uuidString.lowercased() == bootID,
                  build == expectedBuild, marker == nil, try read("relaunch-consumed.json") == nil,
                  try read("preparation.json") == nil, try read("boot-adoption.json") == nil
            else { throw UpdateFailure.recovery }
            if let recovery = try read("recovery.json") {
                guard recovery["schema"] as? String == "machine-monitor/recovery-journal/v1",
                      recovery["target_path"] as? String == target.path,
                      ["accepted", "rolled-back"].contains(recovery["phase"] as? String ?? "")
                else { throw UpdateFailure.recovery }
            }
            // Caller validates the manifest, signed runtime binding, identity,
            // build/version and platform before this durable adoption intent.
            try verify(expectedBuild)
            try write("boot-adoption.json", ["schema": "machine-monitor/boot-adoption/v1", "transaction_id": transaction,
                "target_path": target.path, "old_boot_id": previousBoot, "new_boot_id": bootID, "expected_build": expectedBuild])
            needsAcceptance = true; disposition = .ordinary
            try transition("replacement-observed")
            return disposition
        }
        guard ["installer-pending", "replacement-observed"].contains(phase), build == expectedBuild,
              j["boot_id"] as? String == bootID else { throw UpdateFailure.recovery }
        try verify(expectedBuild)
        if let marker {
            guard marker["schema"] as? String == "machine-monitor/relaunch/v1",
                  marker["transaction_id"] as? String == transaction, marker["target_path"] as? String == target.path,
                  marker["old_build"] as? Int == oldBuild, marker["expected_build"] as? Int == expectedBuild,
                  marker["boot_id"] as? String == bootID, let created = marker["created_at"] as? Double,
                  now.timeIntervalSince1970 >= created, now.timeIntervalSince1970 - created <= 600
            else { throw UpdateFailure.recovery }
            disposition = .dormant
        } else {
            guard try read("relaunch-consumed.json") == nil else { throw UpdateFailure.recovery }
            disposition = .ordinary // positively verified install-on-quit, explicit next open
        }
        needsAcceptance = true
        try transition("replacement-observed")
        return disposition
    }
    func adoptPrepared(transaction: String, manifest: UpdateManifest, generation: UInt64) throws {
        try acquire()
        guard let j = try read("journal.json"), j["schema"] as? String == "machine-monitor/update-journal/v1",
              j["transaction_id"] as? String == transaction, j["target_path"] as? String == target.path,
              j["boot_id"] as? String == bootID, j["phase"] as? String == "prepared",
              j["credential_generation"] as? UInt64 == generation,
              let expected = j["expected"] as? [String: Any], NSDictionary(dictionary: expected).isEqual(to: manifest.dictionary)
        else { throw UpdateFailure.recovery }
        journal = j
    }
    func transition(_ phase: String) throws {
        guard var j = journal else { throw UpdateFailure.recovery }
        j["phase"] = phase; try write("journal.json", j); journal = j
    }
    func markActualRelaunch(now: Date = Date()) throws {
        guard let j = journal, j["phase"] as? String == "installer-pending",
              let expected = j["expected"] as? [String: Any], let old = j["old"] as? [String: Any]
        else { throw UpdateFailure.recovery }
        try write("relaunch.json", ["schema": "machine-monitor/relaunch/v1", "transaction_id": j["transaction_id"]!,
            "target_path": target.path, "old_build": old["build"]!, "expected_build": expected["build"]!,
            "boot_id": bootID, "created_at": now.timeIntervalSince1970])
    }
    func acceptReadiness(build: Int) throws {
        guard needsAcceptance, let j = journal else { return }
        try write("acceptance.json", ["schema": "machine-monitor/update-acceptance/v1", "transaction_id": j["transaction_id"]!,
            "target_path": target.path, "build": build, "boot_id": bootID])
        // Removing the consumed marker before accepting leaves a recoverable pending journal on crash.
        unlink(directory.appendingPathComponent("relaunch-consumed.json").path); try syncDirectory()
        try transition("accepted"); try cleanupBootAdoption(transaction: j["transaction_id"] as! String, build: build)
        needsAcceptance = false
    }
    private func cleanupBootAdoption(transaction: String, build: Int) throws {
        guard let adoption = try read("boot-adoption.json") else { return }
        guard Set(adoption.keys) == Set(["schema", "transaction_id", "target_path", "old_boot_id", "new_boot_id", "expected_build"]),
              adoption["schema"] as? String == "machine-monitor/boot-adoption/v1", adoption["transaction_id"] as? String == transaction,
              adoption["target_path"] as? String == target.path, adoption["expected_build"] as? Int == build,
              let oldBoot = adoption["old_boot_id"] as? String, let newBoot = adoption["new_boot_id"] as? String,
              oldBoot != newBoot, UUID(uuidString: oldBoot)?.uuidString.lowercased() == oldBoot,
              UUID(uuidString: newBoot)?.uuidString.lowercased() == newBoot,
              let receipt = try read("acceptance.json"), receipt["transaction_id"] as? String == transaction,
              receipt["target_path"] as? String == target.path, receipt["build"] as? Int == build,
              receipt["boot_id"] as? String == newBoot
        else { throw UpdateFailure.recovery }
        guard unlink(directory.appendingPathComponent("boot-adoption.json").path) == 0 else { throw UpdateFailure.recovery }
        try syncDirectory()
    }
    static func currentBootID() throws -> String {
        var length = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &length, nil, 0) == 0, length > 0, length < 128 else { throw UpdateFailure.recovery }
        var bytes = [CChar](repeating: 0, count: length)
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &length, nil, 0) == 0 else { throw UpdateFailure.recovery }
        let value = String(cString: bytes).lowercased()
        guard UUID(uuidString: value) != nil else { throw UpdateFailure.recovery }; return value
    }
}
