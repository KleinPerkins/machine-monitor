import Foundation
import Darwin
import CryptoKit

// No global URLProtocol hook, trust override, shared cookie store or credential forwarding.
final class UpdateTransport: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let origin: URL
    private let now: () -> Date
    private var session: URLSession!
    private var task: URLSessionDataTask?
    private var completion: ((Result<Data, Error>) -> Void)?
    private var bytes = Data()
    private var count = 0
    private var limit = 0
    private var expectedSize: Int?
    private var output: FileHandle?
    private var outputURL: URL?
    private var assemblyID: UUID?
    private var assemblyCancel: (() -> Void)?
    init(origin: URL, fixtureProtocols: [AnyClass] = [], now: @escaping () -> Date = Date.init) {
        self.origin = origin; self.now = now; super.init()
        let config = URLSessionConfiguration.ephemeral
        if !fixtureProtocols.isEmpty { config.protocolClasses = fixtureProtocols }
        config.httpShouldSetCookies = false; config.httpCookieStorage = nil
        config.urlCache = nil; config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCredentialStorage = nil
        config.timeoutIntervalForRequest = 30; config.timeoutIntervalForResource = 300
        config.httpMaximumConnectionsPerHost = 1
        let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1; queue.underlyingQueue = .main
        session = URLSession(configuration: config, delegate: self, delegateQueue: queue)
    }
    func cancel() {
        let cancelAssembly = assemblyCancel; assemblyCancel = nil; assemblyID = nil
        task?.cancel(); finish(.failure(UpdateFailure.cancelled)); cancelAssembly?()
    }
    func close() { cancel(); session.invalidateAndCancel() }
    func download(archive: UpdateManifest.Archive, token: String, output: URL,
                  completion: @escaping (Result<Data, Error>) -> Void) {
        precondition(Thread.isMainThread)
        guard task == nil, assemblyID == nil else { completion(.failure(UpdateFailure.busy)); return }
        let fd = open(output.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { completion(.failure(UpdateFailure.invalid("private download storage"))); return }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var identity = stat(); guard fstat(fd, &identity) == 0 else { try? handle.close(); completion(.failure(UpdateFailure.invalid("download identity"))); return }
        let id = UUID(), deadline = now().addingTimeInterval(300)
        assemblyID = id; var finished = false; var timer: DispatchWorkItem?
        func current() throws {
            guard !finished, assemblyID == id, now() < deadline else { throw UpdateFailure.cancelled }
        }
        func done(_ outcome: Result<Data, Error>) {
            guard !finished else { return }; finished = true; timer?.cancel(); timer = nil
            if assemblyID == id { assemblyID = nil; assemblyCancel = nil }
            var result = outcome
            do { try handle.close() } catch { result = .failure(UpdateFailure.invalid("download close failed")) }
            if case .failure = result {
                var live = stat()
                if lstat(output.path, &live) == 0, live.st_dev == identity.st_dev, live.st_ino == identity.st_ino {
                    _ = unlink(output.path)
                }
            }
            completion(result)
        }
        assemblyCancel = { done(.failure(UpdateFailure.cancelled)) }
        timer = DispatchWorkItem { [weak self] in
            guard !finished else { return }
            self?.cancel()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 300, execute: timer!)
        func endpoint(_ suffix: String) throws -> URL {
            guard archive.path.range(of: "^/v1/apps/com\\.kleinperkins\\.machine-monitor/releases/[A-Za-z0-9_-]{1,128}/(archive|package)$", options: .regularExpression) != nil,
                  let url = URL(string: origin.absoluteString + archive.path + suffix)
            else { throw UpdateFailure.invalid("piece address") }
            return url
        }
        func next(_ descriptor: UpdatePieceDescriptor, _ index: Int) {
            guard !finished else { return }
            do {
                try current()
                if index == descriptor.parts.count {
                    try handle.synchronize(); try current(); done(.success(Data())); return
                }
                let part = descriptor.parts[index]
                request(url: try endpoint("/parts/\(index)"), token: token, limit: part.size, expectedSize: part.size) { result in
                    guard !finished else { return }
                    do {
                        try current(); let data = try result.get()
                        guard data.count == part.size, SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == part.sha256
                        else { throw UpdateFailure.invalid("piece hash/length") }
                        try current(); try handle.write(contentsOf: data); try current()
                        next(descriptor, index + 1)
                    } catch { done(.failure(error)) }
                }
            } catch { done(.failure(error)) }
        }
        do {
            request(url: try endpoint("/parts"), token: token, limit: UpdatePieceDescriptor.metadataLimit) { result in
                guard !finished else { return }
                do { try current(); let value = try UpdatePieceDescriptor.parse(result.get(), archive: archive); try current(); next(value, 0) }
                catch { done(.failure(error)) }
            }
        } catch { done(.failure(error)) }
    }
    func request(url: URL, token: String, body: Data? = nil, limit: Int,
                 output: URL? = nil, expectedSize: Int? = nil,
                 completion: @escaping (Result<Data, Error>) -> Void) {
        precondition(Thread.isMainThread)
        guard task == nil else { completion(.failure(UpdateFailure.busy)); return }
        guard url.scheme == "https", url.host == origin.host, url.port == origin.port,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              token.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil
        else { completion(.failure(UpdateFailure.invalid("unapproved address"))); return }
        self.completion = completion; self.limit = limit; self.expectedSize = expectedSize
        count = 0; bytes = Data(); outputURL = output
        if let output {
            let fd = open(output.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { finish(.failure(UpdateFailure.invalid("private download storage"))); return }
            self.output = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        }
        var request = URLRequest(url: url)
        request.httpMethod = body == nil ? "GET" : "POST"; request.httpBody = body
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        request.setValue("MachineMonitor-Update/1.0", forHTTPHeaderField: "User-Agent")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        task = session.dataTask(with: request); task?.resume()
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard dataTask === task, let http = response as? HTTPURLResponse,
              http.url?.scheme == "https", http.url?.host == origin.host, http.url?.port == origin.port,
              http.statusCode == 200, response.expectedContentLength <= Int64(limit),
              expectedSize == nil || response.expectedContentLength == Int64(expectedSize!),
              (http.value(forHTTPHeaderField: "Content-Encoding") ?? "identity").lowercased() == "identity"
        else {
            completionHandler(.cancel)
            let status = (response as? HTTPURLResponse)?.statusCode
            finish(.failure(status == 401 || status == 403 ? UpdateFailure.access : UpdateFailure.network)); return
        }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard dataTask === task else { return }
        guard data.count <= limit - count else { dataTask.cancel(); finish(.failure(UpdateFailure.invalid("response too large"))); return }
        count += data.count
        do { if let output { try output.write(contentsOf: data) } else { bytes.append(data) } }
        catch { dataTask.cancel(); finish(.failure(UpdateFailure.invalid("download write failed"))) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard task === self.task else { return }
        if error != nil { finish(.failure(UpdateFailure.network)); return }
        guard expectedSize == nil || expectedSize == count else { finish(.failure(UpdateFailure.invalid("incomplete download"))); return }
        do { try output?.synchronize(); finish(.success(bytes)) }
        catch { finish(.failure(UpdateFailure.invalid("download persistence failed"))) }
    }
    private func finish(_ result: Result<Data, Error>) {
        guard let callback = completion else { return }
        completion = nil; task = nil
        try? output?.close(); output = nil
        if case .failure = result, let outputURL { try? FileManager.default.removeItem(at: outputURL) }
        outputURL = nil; bytes = Data(); count = 0
        callback(result)
    }
}
