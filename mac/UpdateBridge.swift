import Foundation
import Network

// One admitted archive and one generated feed; no external token enters this object.
final class UpdateLoopbackBridge {
    private let queue = DispatchQueue(label: "machine-monitor.update-bridge")
    private let archive: UpdateVerifiedArchive
    private let manifest: UpdateManifest
    private let capability = UUID().uuidString.replacingOccurrences(of: "-", with: "") + UUID().uuidString.replacingOccurrences(of: "-", with: "")
    private var listener: NWListener?
    private var connections: [ObjectIdentifier: NWConnection] = [:]
    private var requests = 0
    private var port: UInt16 = 0
    private var expiry: DispatchWorkItem?
    private var stopped = false
    var feedURL: URL? { port == 0 ? nil : URL(string: "http://127.0.0.1:\(port)/\(capability)/appcast.xml") }
    init(archive: UpdateVerifiedArchive, manifest: UpdateManifest) { self.archive = archive; self.manifest = manifest }
    func start(_ completion: @escaping (Result<URL, Error>) -> Void) {
        do {
            try archive.verifyUnchanged()
            guard try archive.sha256() == manifest.archive.sha256 else { throw UpdateFailure.invalid("archive changed") }
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
            let listener = try NWListener(using: parameters)
            self.listener = listener
            var delivered = false
            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    guard !delivered, let port = listener.port else { return }
                    delivered = true; self.port = port.rawValue
                    DispatchQueue.main.async { completion(.success(self.feedURL!)) }
                case .failed:
                    guard !delivered else { return }; delivered = true
                    DispatchQueue.main.async { completion(.failure(UpdateFailure.network)) }
                    self.stopOnQueue()
                default: break
                }
            }
            listener.newConnectionHandler = { [weak self] in self?.accept($0) }
            listener.start(queue: queue)
            let expiry = DispatchWorkItem { [weak self] in self?.stopOnQueue() }
            self.expiry = expiry; queue.asyncAfter(deadline: .now() + 600, execute: expiry)
        } catch { completion(.failure(error)) }
    }
    func stop() { queue.async { [weak self] in self?.stopOnQueue() } }
    private func stopOnQueue() {
        stopped = true; expiry?.cancel(); expiry = nil; listener?.cancel(); listener = nil
        for connection in connections.values { connection.cancel() }; connections.removeAll()
    }
    private func accept(_ connection: NWConnection) {
        guard !stopped, connections.count < 4, requests < 16,
              case .hostPort(let host, _) = connection.endpoint,
              host == NWEndpoint.Host("127.0.0.1") else { connection.cancel(); return }
        requests += 1
        let id = ObjectIdentifier(connection); connections[id] = connection
        connection.stateUpdateHandler = { [weak self] state in
            if case .cancelled = state { self?.connections.removeValue(forKey: id) }
            if case .failed = state { connection.cancel(); self?.connections.removeValue(forKey: id) }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 60) { connection.cancel() }
        receive(connection, buffer: Data())
    }
    private func receive(_ connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192 - buffer.count) { [weak self] data, _, complete, error in
            guard let self else { connection.cancel(); return }
            var accumulated = buffer; if let data { accumulated.append(data) }
            guard error == nil, accumulated.count < 8192 else { connection.cancel(); return }
            if let boundary = accumulated.range(of: Data("\r\n\r\n".utf8)) {
                guard boundary.upperBound == accumulated.count else { connection.cancel(); return }
                self.respond(connection, request: accumulated)
            } else if complete { connection.cancel() }
            else { self.receive(connection, buffer: accumulated) }
        }
    }
    static func parseRequest(_ data: Data, host: String, feedPath: String, archivePath: String) -> (Bool, Bool)? {
        guard let text = String(data: data, encoding: .ascii), !text.contains("\0") else { return nil }
        let lines = text.components(separatedBy: "\r\n")
        let first = lines[0].components(separatedBy: " ")
        guard first.count == 3, ["GET", "HEAD"].contains(first[0]), first[2] == "HTTP/1.1",
              [feedPath, archivePath].contains(first[1]) else { return nil }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() where !line.isEmpty {
            guard !line.hasPrefix(" "), !line.hasPrefix("\t"), let colon = line.firstIndex(of: ":") else { return nil }
            let name = String(line[..<colon]).lowercased()
            guard !name.isEmpty, headers[name] == nil else { return nil }
            headers[name] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        guard headers["host"] == host, headers["transfer-encoding"] == nil,
              headers["content-length"] == nil || headers["content-length"] == "0",
              headers["origin"] == nil, headers["range"] == nil else { return nil }
        return (first[0] == "HEAD", first[1] == feedPath)
    }
    private func respond(_ connection: NWConnection, request: Data) {
        let host = "127.0.0.1:\(port)"
        guard let (head, feed) = Self.parseRequest(request, host: host, feedPath: "/\(capability)/appcast.xml", archivePath: "/\(capability)/archive.zip") else { connection.cancel(); return }
        do { try archive.verifyUnchanged() } catch { connection.cancel(); return }
        let feedData = Data(appcast(host: host).utf8)
        let length = feed ? feedData.count : archive.size
        let header = "HTTP/1.1 200 OK\r\nContent-Length: \(length)\r\nContent-Type: \(feed ? "application/rss+xml" : "application/zip")\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n"
        connection.send(content: Data(header.utf8), completion: .contentProcessed { [weak self] error in
            guard let self, error == nil else { connection.cancel(); return }
            if head { connection.cancel() }
            else if feed { connection.send(content: feedData, completion: .contentProcessed { _ in connection.cancel() }) }
            else { self.sendArchive(connection, offset: 0) }
        })
    }
    private func sendArchive(_ connection: NWConnection, offset: Int) {
        guard !stopped, offset < archive.size else { connection.cancel(); return }
        do {
            try archive.verifyUnchanged()
            let data = try archive.read(offset: offset, count: min(65_536, archive.size - offset))
            connection.send(content: data, completion: .contentProcessed { [weak self] error in
                guard error == nil else { connection.cancel(); return }
                self?.sendArchive(connection, offset: offset + data.count)
            })
        } catch { connection.cancel() }
    }
    private func appcast(host: String) -> String {
        // Only integer/version identity and base64 signature enter generated XML.
        """
        <?xml version="1.0" encoding="utf-8"?>
        <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><title>Machine Monitor</title><item><title>Machine Monitor update</title><sparkle:version>\(manifest.build)</sparkle:version><sparkle:minimumSystemVersion>26.0</sparkle:minimumSystemVersion><enclosure url="http://\(host)/\(capability)/archive.zip" length="\(manifest.archive.size)" type="application/octet-stream" sparkle:edSignature="\(manifest.archive.ed25519_signature)" /></item></channel></rss>
        """
    }
}
