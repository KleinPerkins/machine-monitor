import AppKit
import WebKit

// A native window and lifetime owner for the bundled, on-demand local service.
final class MonitorApp: NSObject, NSApplicationDelegate, NSWindowDelegate,
                        WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
    var window: NSWindow!
    var web: WKWebView!
    var placeholder: NSView!
    var message: NSTextField!
    var retry: NSButton!
    var service: Process?
    var origin: URL?
    var readyBytes = Data()
    var generation = 0
    var loaded = false
    var firstScanStarted = false
    var firstScanRequested = false
    var quitting = false
    var serviceLog = ""
    var verifyPath: String?
    var verification: [String: Any] = [:]
    var verificationStarted = false
    var updates: UpdateCoordinator?
    var startupInstallLease: String?
    var updateScheduleStarted = false
    var pendingAccessFiles: [URL] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--verify"), args.count > i + 1 { verifyPath = args[i + 1] }
        updates = UpdateCoordinator.bootstrap()
        if updates?.startupDisposition == .locked { NSApp.terminate(nil); return }
        if let i = args.firstIndex(of: "--import-access-file"), args.count > i + 1 {
            pendingAccessFiles.append(URL(fileURLWithPath: args[i + 1]))
        }
        updates?.admitInstall = { [weak self] transaction, completion in
            guard let self else { completion(.unavailable); return }
            self.requestInstallAdmission(transaction, completion: completion)
        }
        updates?.releaseInstall = { [weak self] token, completion in
            guard let self else { completion(false); return }
            self.releaseInstallAdmission(token, completion: completion)
        }
        updates?.isVisible = { [weak self] in
            guard let self else { return false }
            return NSApp.isActive && self.window?.isVisible == true && self.window?.isMiniaturized == false && self.window?.occlusionState.contains(.visible) == true
        }
        updates?.onStateChange = { [weak self] in self?.updateStateChanged() }
        NSApp.setActivationPolicy(.regular)
        buildMenu()
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
        configuration.userContentController.add(self, name: "monitorApp")
        configuration.userContentController.addUserScript(WKUserScript(
            source: "window.machineMonitorDesktop = true;", injectionTime: .atDocumentStart, forMainFrameOnly: true))
        web = WKWebView(frame: .zero, configuration: configuration)
        web.navigationDelegate = self
        web.uiDelegate = self
        web.allowsBackForwardNavigationGestures = false
        web.translatesAutoresizingMaskIntoConstraints = false
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1240, height: 840),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Machine Monitor"
        window.minSize = NSSize(width: 420, height: 440)
        window.delegate = self
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("MachineMonitorWindow")
        let content = window.contentView!
        content.addSubview(web)
        NSLayoutConstraint.activate([
            web.leadingAnchor.constraint(equalTo: content.leadingAnchor), web.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            web.topAnchor.constraint(equalTo: content.topAnchor), web.bottomAnchor.constraint(equalTo: content.bottomAnchor)])
        placeholder = NSView(frame: content.bounds)
        placeholder.autoresizingMask = [.width, .height]
        content.addSubview(placeholder)
        let title = NSTextField(labelWithString: "Machine Monitor")
        title.font = .systemFont(ofSize: 26, weight: .semibold)
        message = NSTextField(wrappingLabelWithString: "Starting your local monitor…")
        message.alignment = .center
        message.textColor = .secondaryLabelColor
        message.font = .systemFont(ofSize: 14)
        retry = NSButton(title: "Try again", target: self, action: #selector(reloadMonitor))
        retry.bezelStyle = .rounded
        let stack = NSStackView(views: [title, message, retry])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 18
        stack.translatesAutoresizingMaskIntoConstraints = false
        placeholder.addSubview(stack)
        NSLayoutConstraint.activate([stack.centerXAnchor.constraint(equalTo: placeholder.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: placeholder.centerYAnchor),
            stack.widthAnchor.constraint(lessThanOrEqualToConstant: 480),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: placeholder.leadingAnchor, constant: 28),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: placeholder.trailingAnchor, constant: -28)])
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        startService()
        let accessFiles = pendingAccessFiles
        pendingAccessFiles.removeAll()
        for file in accessFiles { updates?.importAccessFile(file) }
        if verifyPath != nil {
            DispatchQueue.main.asyncAfter(deadline: .now() + 65) { [weak self] in
                self?.verificationFailed("Native acceptance check timed out")
            }
        }
    }

    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        guard filenames.count == 1 else { sender.reply(toOpenOrPrint: .failure); return }
        let url = URL(fileURLWithPath: filenames[0])
        if let updates { updates.importAccessFile(url) }
        else { pendingAccessFiles.append(url) }
        sender.reply(toOpenOrPrint: .success)
    }

    func buildMenu() {
        let menu = NSMenu()
        let appItem = NSMenuItem()
        let appMenu = NSMenu(title: "Machine Monitor")
        appMenu.addItem(withTitle: "About Machine Monitor", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        updates?.appendMenu(to: appMenu)
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide Machine Monitor", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit Machine Monitor", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        menu.addItem(appItem)
        let editItem = NSMenuItem()
        let edit = NSMenu(title: "Edit")
        for (title, action, key) in [("Cut", "cut:", "x"), ("Copy", "copy:", "c"), ("Paste", "paste:", "v"), ("Select All", "selectAll:", "a")] {
            edit.addItem(withTitle: title, action: Selector(action), keyEquivalent: key)
        }
        editItem.submenu = edit
        menu.addItem(editItem)
        let viewItem = NSMenuItem()
        let view = NSMenu(title: "View")
        let reload = view.addItem(withTitle: "Reload Monitor", action: #selector(reloadMonitor), keyEquivalent: "r")
        reload.target = self
        viewItem.submenu = view
        menu.addItem(viewItem)
        let windowItem = NSMenuItem()
        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowItem.submenu = windowMenu
        menu.addItem(windowItem)
        NSApp.mainMenu = menu
        NSApp.windowsMenu = windowMenu
    }

    func presentMessage(_ text: String, canRetry: Bool) {
        placeholder.isHidden = false
        web.isHidden = true
        message.stringValue = text
        retry.isHidden = !canRetry
    }

    func startService() {
        guard service?.isRunning != true else { return }
        guard updates?.allowsCollectorService != false else {
            presentMessage(updates?.status ?? "Update recovery is required.", canRetry: false); return
        }
        generation += 1
        let expected = generation
        loaded = false
        startupInstallLease = nil
        origin = nil
        readyBytes = Data()
        serviceLog = ""
        presentMessage("Starting your local monitor…", canRetry: false)
        guard let resource = Bundle.main.resourceURL else {
            presentMessage("The app’s local service is missing. Reinstall Machine Monitor.", canRetry: true); return
        }
        let child = Process()
        child.executableURL = resource.appendingPathComponent("service/monitor-service")
        child.arguments = ["--port", "0", "--desktop", "--parent-pid", String(getpid())]
        if let transaction = updates?.startupInstallTransactionID {
            child.arguments?.append(contentsOf: ["--install-transaction", transaction])
        }
        // No inherited Python paths, environment secrets or shell are needed by the frozen service.
        child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"]
        child.currentDirectoryURL = resource
        let output = Pipe(), errors = Pipe()
        child.standardOutput = output
        child.standardError = errors
        child.standardInput = FileHandle.nullDevice
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            DispatchQueue.main.async { self?.readReady(data, generation: expected) }
        }
        errors.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            DispatchQueue.main.async {
                guard let self, self.generation == expected else { return }
                self.serviceLog = String((self.serviceLog + String(decoding: data, as: UTF8.self)).suffix(8192))
            }
        }
        child.terminationHandler = { [weak self] process in
            output.fileHandleForReading.readabilityHandler = nil
            errors.fileHandleForReading.readabilityHandler = nil
            DispatchQueue.main.async {
                guard let self, self.generation == expected, !self.quitting else { return }
                self.loaded = false
                if self.updates?.allowsCollectorService == false {
                    self.presentMessage(self.updates?.status ?? "An update is in progress.", canRetry: false)
                } else {
                    self.presentMessage("The local monitor stopped. Click Try again to reopen it.", canRetry: true)
                }
                if self.verifyPath != nil { self.verificationFailed("Service exited: \(process.terminationStatus): \(self.serviceLog)") }
            }
        }
        service = child
        do { try child.run() }
        catch {
            service = nil
            presentMessage("The local service couldn’t start. Click Try again, or reinstall the app.", canRetry: true)
            if verifyPath != nil { verificationFailed(error.localizedDescription) }
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self, self.generation == expected, self.origin == nil, !self.quitting else { return }
            self.service?.terminate()
            self.presentMessage("The local monitor took too long to start. Please try again.", canRetry: true)
        }
    }

    func readReady(_ data: Data, generation expected: Int) {
        guard generation == expected, origin == nil, service?.isRunning == true else { return }
        readyBytes.append(data)
        guard readyBytes.count < 16384 else { service?.terminate(); return }
        guard let text = String(data: readyBytes, encoding: .utf8), let end = text.firstIndex(of: "\n") else { return }
        let line = String(text[..<end]), prefix = "MACHINE_MONITOR_READY "
        guard line.hasPrefix(prefix), let json = String(line.dropFirst(prefix.count)).data(using: .utf8),
              let value = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
              value["pid"] as? Int == Int(service!.processIdentifier), let port = value["port"] as? Int, (1...65535).contains(port),
              let url = URL(string: "http://127.0.0.1:\(port)/") else { service?.terminate(); return }
        if updates?.startupInstallTransactionID != nil {
            guard let lease = value["install_lease"] as? String, (32...128).contains(lease.count) else {
                service?.terminate(); presentMessage("Update readiness could not be protected. Open Machine Monitor Recovery.", canRetry: false); return
            }
            startupInstallLease = lease
        }
        origin = url
        web.load(URLRequest(url: url))
    }

    @objc func reloadMonitor() {
        guard updates?.allowsCollectorService != false else { return }
        if service?.isRunning == true, let origin {
            loaded = false
            web.load(URLRequest(url: origin))
        } else { startService() }
    }

    func isLocal(_ url: URL?) -> Bool {
        guard let url, let origin else { return false }
        return url.scheme == origin.scheme && url.host == origin.host && url.port == origin.port
    }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame, isLocal(message.frameInfo.request.url), let command = message.body as? String else { return }
        if command == "quit" { NSApp.terminate(nil) }
        if command == "ready" {
            loaded = true
            updates?.serviceReady(startupLease: startupInstallLease)
            placeholder.isHidden = true
            web.isHidden = false
            startFirstScanIfVisible()
            startUpdateScheduleIfReady()
        }
    }

    func updateStateChanged() {
        guard window != nil, !quitting else { return }
        if updates?.startupDisposition == .recovery {
            stopWhenHidden()
            presentMessage(updates?.status ?? "Open Machine Monitor Recovery to resolve the installation.", canRetry: false)
        } else {
            startFirstScanIfVisible()
            startUpdateScheduleIfReady()
        }
    }

    func startUpdateScheduleIfReady() {
        guard loaded, !updateScheduleStarted, !quitting else { return }
        let adoptedDormant = updates?.startupDisposition == .dormant && updates?.startupInstallTransactionID == nil
        guard firstScanStarted || adoptedDormant else { return }
        updateScheduleStarted = true
        updates?.dashboardReady()
    }

    func requestInstallAdmission(_ transaction: String, completion: @escaping (UpdateInstallAdmission) -> Void) {
        guard loaded, service?.isRunning == true, !quitting else { completion(.unavailable); return }
        web.callAsyncJavaScript("""
            try {
                const response=await fetch('/api/install-admit',{method:'POST',headers:{'Content-Type':'application/json','X-Monitor':'1'},body:JSON.stringify({transaction}),signal:AbortSignal.timeout(2500)});
                const state=await response.json();
                if(response.ok && typeof state.install_lease==='string') {accept(state,true);return {status:'admitted',lease:state.install_lease};}
                if(response.status===409 && state.installing===false)return {status:'busy'};
                return {status:'unavailable'};
            } catch {return {status:'unavailable'};}
            """, arguments: ["transaction": transaction], in: nil, in: .page) { result in
            guard case .success(let raw) = result, let value = raw as? [String: Any] else { completion(.unavailable); return }
            if value["status"] as? String == "admitted", let token = value["lease"] as? String {
                completion(.admitted(token))
            } else if value["status"] as? String == "busy" { completion(.busy) }
            else { completion(.unavailable) }
        }
    }

    func releaseInstallAdmission(_ token: String, completion: @escaping (Bool) -> Void) {
        guard loaded, service?.isRunning == true, !quitting else { completion(false); return }
        web.callAsyncJavaScript("""
            try {const state=await api('install-release',{install_lease:token});accept(state,true);return state.installing===false;}
            catch {return false;}
            """, arguments: ["token": token], in: nil, in: .page) { result in
            if case .success(let value) = result { completion(value as? Bool == true) }
            else { completion(false) }
        }
    }

    func startFirstScanIfVisible() {
        guard loaded, !firstScanStarted, !firstScanRequested, NSApp.isActive, window.isVisible, !window.isMiniaturized,
              window.occlusionState.contains(.visible), !quitting, updates?.suppressAutomaticScan != true else { return }
        firstScanRequested = true
        // AppKit visibility changes reach WebKit asynchronously. Wait for WebKit's
        // actual visibility before invoking the frontend's hidden-page guard.
        web.callAsyncJavaScript("""
            for(let i=0;i<100 && document.hidden;i++)await new Promise(resolve=>setTimeout(resolve,20));
            if(document.hidden)return false;
            await start(30);return true;
            """, arguments: [:], in: nil, in: .page) { [weak self] result in
            guard let self, !self.quitting else { return }
            self.firstScanRequested = false
            switch result {
            case .success(let attempted):
                if attempted as? Bool == true {
                    self.firstScanStarted = true
                    self.startUpdateScheduleIfReady()
                    if self.verifyPath != nil && !self.verificationStarted {
                        self.verificationStarted = true; self.runVerification()
                    }
                }
            case .failure(let error):
                if self.verifyPath != nil { self.verificationFailed(error.localizedDescription) }
            }
        }
    }

    func stopWhenHidden() {
        updates?.visibilityChanged()
        guard loaded else { return }
        web.evaluateJavaScript("leave()", completionHandler: nil)
    }
    func applicationDidBecomeActive(_ notification: Notification) { updates?.visibilityChanged(); startFirstScanIfVisible() }
    func applicationDidHide(_ notification: Notification) { stopWhenHidden() }
    func windowDidMiniaturize(_ notification: Notification) { stopWhenHidden() }
    func windowDidChangeOcclusionState(_ notification: Notification) {
        if window.occlusionState.contains(.visible) { startFirstScanIfVisible() } else { stopWhenHidden() }
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        window.deminiaturize(nil)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        return true
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !quitting else { return .terminateNow }
        quitting = true
        updates?.shutdown()
        stopWhenHidden()
        guard let child = service, child.isRunning else { return .terminateNow }
        child.terminate()
        // Let SIGTERM cancel and join collection before falling back to our own child's PID.
        DispatchQueue.global().async {
            let until = Date().addingTimeInterval(2)
            while child.isRunning && Date() < until { Thread.sleep(forTimeInterval: 0.025) }
            if child.isRunning { kill(child.processIdentifier, SIGKILL) }
            child.waitUntilExit()
            DispatchQueue.main.async { NSApp.reply(toApplicationShouldTerminate: true) }
        }
        return .terminateLater
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if isLocal(action.request.url) { decisionHandler(.allow); return }
        if action.navigationType == .linkActivated, let url = action.request.url,
           ["https", "http"].contains(url.scheme ?? "") { NSWorkspace.shared.open(url) }
        decisionHandler(.cancel)
    }
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if action.navigationType == .linkActivated, let url = action.request.url,
           ["https", "http"].contains(url.scheme ?? ""), !isLocal(url) { NSWorkspace.shared.open(url) }
        return nil
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        guard !quitting, (error as NSError).code != NSURLErrorCancelled else { return }
        presentMessage("Couldn’t open the monitor. Click Try again to reconnect.", canRetry: true)
        if verifyPath != nil { verificationFailed(error.localizedDescription) }
    }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        stopWhenHidden()
        loaded = false
        presentMessage("The monitor window needs to reload. Your local service is still available.", canRetry: true)
    }

    // Explicit local acceptance mode exercises this real WKWebView, not a browser substitute.
    func js(_ body: String, then: @escaping ([String: Any]) -> Void) {
        web.callAsyncJavaScript(body, arguments: [:], in: nil, in: .page) { [weak self] result in
            switch result {
            case .success(let value):
                guard let object = value as? [String: Any] else { self?.verificationFailed("Invalid acceptance result"); return }
                then(object)
            case .failure(let error): self?.verificationFailed(error.localizedDescription)
            }
        }
    }
    let probe = """
      const s=await api('state'),f=s.frames.at(-1);
      return {active:s.active,count:s.count,remaining:s.remaining,scan:s.scan,pid:s.service_pid,
        startDisabled:document.getElementById('start').disabled,hidden:document.hidden,
        cpuC:f?.temperatures?.cpu_c??null,gpuC:f?.temperatures?.gpu_c??null,
        sensors:[f?.temperatures?.cpu_sensors?.length??0,f?.temperatures?.gpu_sensors?.length??0],
        intervals:s.frames.slice(1).map((f,i)=>f.at-s.frames[i].at),
        error:document.getElementById('error').hidden?null:document.getElementById('error').textContent};
      """
    func runVerification() {
        verification["bundle"] = Bundle.main.bundlePath
        verification["window"] = window.title
        verification["nativeWebView"] = true
        verification["url"] = origin?.absoluteString
        DispatchQueue.main.asyncAfter(deadline: .now() + 5.5) { [weak self] in
            guard let self else { return }
            self.js(self.probe) { value in
                guard value["active"] as? Bool == true, (value["count"] as? Int ?? 0) >= 4,
                      value["error"] is NSNull else { self.verificationFailed("Automatic scan failed: \(value)"); return }
                self.verification["automaticScan"] = value
                let snapshot = WKSnapshotConfiguration()
                snapshot.rect = CGRect(x: 0, y: 0, width: self.web.bounds.width, height: min(820, self.web.bounds.height))
                self.web.takeSnapshot(with: snapshot) { image, _ in
                    if let data = image?.tiffRepresentation, let bitmap = NSBitmapImageRep(data: data),
                       let png = bitmap.representation(using: .png, properties: [:]), let path = self.verifyPath {
                        try? png.write(to: URL(fileURLWithPath: path + ".png"))
                    }
                }
                // Reloading the window must preserve the startup-once rule.
                self.verification["initialPID"] = value["pid"]
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 31.5) { [weak self] in
            guard let self else { return }
            self.js(self.probe) { value in
                guard value["active"] as? Bool == false, value["startDisabled"] as? Bool == false,
                      (value["count"] as? Int ?? 0) >= 28 else { self.verificationFailed("30-second completion failed: \(value)"); return }
                self.verification["completedScan"] = value
                self.reloadMonitor()
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    self.js(self.probe) { reload in
                        guard reload["active"] as? Bool == false, reload["pid"] as? Int == value["pid"] as? Int else {
                            self.verificationFailed("Reload started a new service or scan"); return
                        }
                        self.verification["reloadStaysDormant"] = true
                        self.js("await start(30); return {active};") { _ in
                            self.window.miniaturize(nil)
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                                self.js(self.probe) { hidden in
                                    guard hidden["active"] as? Bool == false else { self.verificationFailed("Minimize did not stop collection"); return }
                                    self.verification["minimizeStopsScan"] = true
                                    self.window.deminiaturize(nil)
                                    NSApp.activate(ignoringOtherApps: true)
                                    DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                                        self.js(self.probe) { shown in
                                            guard shown["active"] as? Bool == false else { self.verificationFailed("Restore unexpectedly resumed scan"); return }
                                            self.verification["restoreStaysDormant"] = true
                                            guard self.verifyUpdateSettingsMenu() else { return }
                                            self.verification["passed"] = true
                                            self.saveVerification()
                                            self.window.performClose(nil)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    func verifyUpdateSettingsMenu() -> Bool {
        guard let menu = NSApp.mainMenu?.items.first?.submenu,
              let item = menu.items.first(where: { $0.title == "Update Settings…" }),
              let action = item.action, let target = item.target,
              NSApp.sendAction(action, to: target, from: item),
              let panel = NSApp.windows.first(where: { $0.title == "Update Settings" && $0.isVisible }),
              let scroll = panel.contentView?.subviews.compactMap({ $0 as? NSScrollView }).first,
              let document = scroll.documentView else {
            verificationFailed("Update Settings menu did not open its window"); return false
        }
        panel.contentView?.layoutSubtreeIfNeeded()
        let controls = document.subviews.compactMap { $0 as? NSButton }
        guard document.frame.height > 0,
              controls.contains(where: { $0.title == "Import Access File…" }),
              controls.contains(where: { $0.title == "Automatically check for updates" }) else {
            verificationFailed("Update Settings controls are missing or collapsed"); return false
        }
        panel.performClose(nil)
        guard !panel.isVisible, NSApp.sendAction(action, to: target, from: item), panel.isVisible,
              let check = menu.items.first(where: { $0.title == "Check for Updates…" }),
              let checkAction = check.action, let checkTarget = check.target else {
            verificationFailed("Update Settings did not reopen"); return false
        }
        panel.performClose(nil)
        guard NSApp.sendAction(checkAction, to: checkTarget, from: check), panel.isVisible else {
            verificationFailed("Check for Updates menu did not open Settings"); return false
        }
        panel.performClose(nil)
        verification["updateSettingsMenuOpens"] = true
        verification["updateSettingsCloseReopen"] = true
        verification["checkForUpdatesMenuOpens"] = true
        return true
    }
    func verificationFailed(_ reason: String) {
        guard verifyPath != nil, !quitting else { return }
        verification["passed"] = false
        verification["error"] = reason
        saveVerification()
        NSApp.terminate(nil)
    }
    func saveVerification() {
        if let path = verifyPath, let data = try? JSONSerialization.data(withJSONObject: verification, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
    }
}

@main
struct MachineMonitorApplication {
    @MainActor static func main() {
        let application = NSApplication.shared
        let delegate = MonitorApp()
        application.delegate = delegate
        withExtendedLifetime(delegate) { application.run() }
    }
}
