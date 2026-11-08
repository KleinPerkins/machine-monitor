import AppKit
import Security

@MainActor
final class RecoveryDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var window: NSWindow!
    private let status = NSTextField(wrappingLabelWithString: "")
    private let choose = NSButton(title: "Choose Application…", target: nil, action: nil)
    private let restore = NSButton(title: "Restore Previous Version", target: nil, action: nil)
    private let launch = NSButton(title: "Open Machine Monitor", target: nil, action: nil)
    private let cancel = NSButton(title: "Cancel", target: nil, action: nil)
    private let quitMain = NSButton(title: "Quit Machine Monitor…", target: nil, action: nil)
    private var model = RecoveryPresentation()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 540, height: 360), styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "Machine Monitor Recovery"
        window.delegate = self
        let heading = NSTextField(labelWithString: "Restore a verified previous version")
        heading.font = .systemFont(ofSize: 20, weight: .semibold)
        status.font = .systemFont(ofSize: 14)
        status.setAccessibilityLabel("Recovery status")
        status.setContentCompressionResistancePriority(.required, for: .vertical)
        for button in [choose, restore, launch, quitMain, cancel] { button.target = self; button.bezelStyle = .rounded }
        choose.action = #selector(selectTarget); restore.action = #selector(restoreTarget)
        launch.action = #selector(openRestored); cancel.action = #selector(closeRecovery)
        quitMain.action = #selector(quitMainApplication)
        cancel.keyEquivalent = "\u{1b}"
        let stack = NSStackView(views: [heading, status, choose, restore, launch, quitMain, cancel])
        stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 24), stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -24), stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 24)])
        render(); window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }

    private func render() {
        status.stringValue = model.message
        choose.isEnabled = !model.busy; restore.isEnabled = model.canRestore && !model.busy
        launch.isEnabled = model.canLaunch && !model.busy; cancel.isEnabled = !model.busy
        quitMain.isEnabled = model.targetPath != nil && !model.busy
        NSAccessibility.post(element: status, notification: .valueChanged)
    }

    @objc private func selectTarget() {
        let picker = NSOpenPanel()
        picker.title = "Choose Machine Monitor"; picker.canChooseFiles = true; picker.canChooseDirectories = false
        picker.allowsMultipleSelection = false; picker.allowedContentTypes = [.applicationBundle]
        guard picker.runModal() == .OK, let selected = picker.url else { return }
        model = RecoveryPresentation(); model.targetPath = selected.path
        invoke(action: "status")
    }

    @objc private func restoreTarget() {
        guard model.canRestore else { return }
        let alert = NSAlert(); alert.messageText = "Restore the verified previous version?"
        alert.informativeText = "The current application is saved separately. Recovery will not open the app or start monitoring."
        alert.addButton(withTitle: "Restore Previous Version"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        invoke(action: "restore")
    }

    private func invoke(action: String) {
        guard let target = model.targetPath else { return }
        var request: [String: Any] = ["action": action, "target_path": target]
        if let transaction = model.transactionID { request["transaction_id"] = transaction }
        guard let input = try? JSONSerialization.data(withJSONObject: request),
              let resources = Bundle.main.resourceURL else { return }
        let executable = resources.appendingPathComponent("service/monitor-service")
        model.begin(); model.message = action == "restore" ? "Restoring the verified previous version… Keep Recovery open." : "Verifying previous version and update state…"
        render()
        // A dedicated serial queue keeps the UI responsive. Restore has durable
        // checkpoints; never kill an admitted restoration to implement Cancel.
        DispatchQueue.global(qos: .userInitiated).async {
            let result = RecoveryHelperRunner.run(executable: executable, input: input)
            let response = result
            DispatchQueue.main.async { self.model.consume(response); self.render() }
        }
    }

    /// Cooperative quit only for the exact selected, currently Apple-trusted app.
    @objc private func quitMainApplication() {
        guard let target = model.targetPath else { return }
        let requirementText = "anchor apple generic and identifier \"com.kleinperkins.machine-monitor\" and certificate leaf[subject.OU] = \"J2V7GRV5CM\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        var code: SecStaticCode?; var requirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: target) as CFURL, [], &code) == errSecSuccess,
              SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let code, let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), requirement) == errSecSuccess else {
            model.message = "The selected running application could not be verified. Quit it yourself, then choose the application again."; render(); return
        }
        let running = NSRunningApplication.runningApplications(withBundleIdentifier: "com.kleinperkins.machine-monitor").filter { $0.bundleURL?.standardizedFileURL.path == target }
        let alert = NSAlert(); alert.messageText = "Quit Machine Monitor?"
        alert.informativeText = "This asks the verified selected application to quit normally. An interrupted updater may still require restarting your Mac."
        alert.addButton(withTitle: "Quit Machine Monitor"); alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        for app in running {
            var guest: SecCode?
            let attributes = [kSecGuestAttributePid as String: NSNumber(value: app.processIdentifier)] as CFDictionary
            guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess,
                  let guest, SecCodeCheckValidity(guest, [], requirement) == errSecSuccess else { continue }
            _ = app.terminate()
        }
        model.message = "After Machine Monitor quits, choose the application again to verify recovery readiness."; render()
    }

    @objc private func openRestored() {
        guard model.canLaunch, let target = model.targetPath else { return }
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: target), configuration: NSWorkspace.OpenConfiguration()) { _, _ in }
    }
    @objc private func closeRecovery() { if !model.busy { NSApp.terminate(nil) } }
    func windowShouldClose(_ sender: NSWindow) -> Bool { !model.busy }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply { model.busy ? .terminateCancel : .terminateNow }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { !model.busy }
}

@main
struct MachineMonitorRecovery {
    @MainActor static func main() {
        let delegate = RecoveryDelegate()
        let application = NSApplication.shared
        application.delegate = delegate
        application.run()
        withExtendedLifetime(delegate) {}
    }
}
