import Foundation

/// Pure presentation state. No monitoring, credential, or updater dependencies.
struct RecoveryPresentation {
    var targetPath: String?
    var transactionID: String?
    var message = "Choose the Machine Monitor application to recover."
    var previousVersion: String?
    var canRestore = false
    var canLaunch = false
    var busy = false

    mutating func begin() { busy = true; canRestore = false; canLaunch = false }
    mutating func consume(_ result: [String: Any]) {
        busy = false
        guard result["ok"] as? Bool == true else {
            message = result["error"] as? String ?? "Recovery could not verify this application."
            canRestore = false; canLaunch = false; return
        }
        if let target = result["target_path"] as? String { targetPath = target }
        if let transaction = result["transaction_id"] as? String { transactionID = transaction }
        previousVersion = result["previous_version"] as? String
        canRestore = result["can_restore"] as? Bool == true && transactionID != nil
        canLaunch = result["phase"] as? String == "accepted" && result["restored"] is [String: Any]
        message = result["message"] as? String ?? "Recovery verification finished."
        if let version = previousVersion, canRestore {
            message = "Verified previous version: \(version). The current application and original backup will be retained.\n\n" + message
        }
    }
}

/// Owns only the helper it starts. A timed-out helper exits at a durable recovery
/// boundary; the next explicit restore reconciles the journal before proceeding.
enum RecoveryHelperRunner {
    static func run(executable: URL, input: Data, timeout: TimeInterval = 180) -> [String: Any] {
        var failure: [String: Any] = ["ok": false, "error": "Recovery helper could not finish. Open Recovery again to verify the retained applications."]
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("monitor-recovery-" + UUID().uuidString)
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: directory) }
            let outputURL = directory.appendingPathComponent("response.json")
            guard FileManager.default.createFile(atPath: outputURL.path, contents: nil, attributes: [.posixPermissions: 0o600]) else { return failure }
            let output = try FileHandle(forWritingTo: outputURL)
            defer { try? output.close() }
            let inputPipe = Pipe()
            let process = Process(); process.executableURL = executable; process.arguments = ["--update-recovery"]
            process.standardInput = inputPipe; process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            let completed = DispatchSemaphore(value: 0)
            process.terminationHandler = { _ in completed.signal() }
            try process.run()
            inputPipe.fileHandleForWriting.write(input); try inputPipe.fileHandleForWriting.close()
            if completed.wait(timeout: .now() + timeout) == .timedOut {
                // SIGTERM only our exact child. Never inspect/kill installer PIDs.
                process.terminate(); process.waitUntilExit()
                failure["error"] = "Recovery timed out. Retained applications are preserved. Reopen Recovery to reconcile the interrupted operation."
                return failure
            }
            let attributes = try FileManager.default.attributesOfItem(atPath: outputURL.path)
            guard let length = attributes[.size] as? NSNumber, length.intValue <= 65536 else { return failure }
            let data = try Data(contentsOf: outputURL)
            return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? failure
        } catch { return failure }
    }
}
