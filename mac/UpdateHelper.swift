import Foundation

// Frozen service helper runs preflight/recovery only: never creates the metrics engine.
final class UpdateHelper {
    private var process: Process?
    func cancel() {
        guard let process, process.isRunning else { return }
        process.terminate()
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak process] in
            if let process, process.isRunning { kill(process.processIdentifier, SIGKILL) }
        }
    }
    func run(executable: URL, mode: String, payload: [String: Any], completion: @escaping (Result<[String: Any], Error>) -> Void) {
        guard process == nil, ["--update-preflight", "--update-recovery"].contains(mode) else { completion(.failure(UpdateFailure.busy)); return }
        do {
            let input = try JSONSerialization.data(withJSONObject: payload)
            guard input.count < 262_144 else { throw UpdateFailure.invalid("helper input") }
            let child = Process(), stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
            child.executableURL = executable; child.arguments = [mode]
            child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"]
            child.standardInput = stdin; child.standardOutput = stdout; child.standardError = stderr
            process = child
            // Read concurrently so a helper cannot block on a full output pipe. Bound retained data.
            let outputLock = NSLock(); var output = Data(); var oversized = false
            stdout.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                outputLock.lock()
                if output.count + data.count <= 262_144 { output.append(data) } else { oversized = true; child.terminate() }
                outputLock.unlock()
                if data.isEmpty { handle.readabilityHandler = nil }
            }
            stderr.fileHandleForReading.readabilityHandler = { handle in
                if handle.availableData.isEmpty { handle.readabilityHandler = nil }
                // Helper diagnostics are deliberately not surfaced: state paths are private.
            }
            child.terminationHandler = { [weak self] process in
                stdout.fileHandleForReading.readabilityHandler = nil; stderr.fileHandleForReading.readabilityHandler = nil
                let trailing = stdout.fileHandleForReading.readDataToEndOfFile()
                outputLock.lock(); if output.count + trailing.count <= 262_144 { output.append(trailing) } else { oversized = true }
                let resultData = output; let invalid = oversized; outputLock.unlock()
                DispatchQueue.main.async {
                    self?.process = nil
                    guard process.terminationStatus == 0, !invalid,
                          let result = try? JSONSerialization.jsonObject(with: resultData) as? [String: Any], result["ok"] as? Bool == true
                    else { completion(.failure(UpdateFailure.invalid("preflight or backup preparation failed"))); return }
                    completion(.success(result))
                }
            }
            try child.run(); try stdin.fileHandleForWriting.write(contentsOf: input); try stdin.fileHandleForWriting.close()
            DispatchQueue.main.asyncAfter(deadline: .now() + 180) { [weak self, weak child] in
                guard let child, self?.process === child, child.isRunning else { return }; child.terminate()
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                    if child.isRunning { kill(child.processIdentifier, SIGKILL) }
                }
            }
        } catch { process = nil; completion(.failure(error)) }
    }
}
