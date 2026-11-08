import AppKit
import UniformTypeIdentifiers

final class UpdateSettingsController: NSWindowController {
    private weak var coordinator: UpdateCoordinator?
    private let version = NSTextField(labelWithString: "")
    private let status = NSTextField(wrappingLabelWithString: "")
    private let access = NSTextField(labelWithString: "")
    private let lastCheck = NSTextField(labelWithString: "")
    private var check: NSButton!
    private var importButton: NSButton!
    private var remove: NSButton!
    private var install: NSButton!
    private var discard: NSButton!
    private var automaticCheck: NSButton!
    private var automaticInstall: NSButton!
    init(coordinator: UpdateCoordinator) {
        self.coordinator = coordinator
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 520),
                              styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = "Update Settings"; window.minSize = NSSize(width: 520, height: 480)
        window.isReleasedWhenClosed = false
        super.init(window: window)
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        let content = window.contentView!; content.addSubview(scroll)
        NSLayoutConstraint.activate([scroll.leadingAnchor.constraint(equalTo: content.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: content.trailingAnchor), scroll.topAnchor.constraint(equalTo: content.topAnchor), scroll.bottomAnchor.constraint(equalTo: content.bottomAnchor)])
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 16
        stack.edgeInsets = NSEdgeInsets(top: 24, left: 24, bottom: 24, right: 24); stack.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = stack
        NSLayoutConstraint.activate([stack.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor)])
        version.font = .systemFont(ofSize: 20, weight: .semibold)
        status.setAccessibilityLabel("Update status"); status.setContentHuggingPriority(.defaultLow, for: .horizontal)
        status.maximumNumberOfLines = 0
        status.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -48).isActive = true
        check = button("Check Now", #selector(checkNow))
        importButton = button("Import Access File…", #selector(importFile))
        remove = button("Remove Access…", #selector(removeAccess))
        install = button("Install after scan", #selector(installUpdate))
        discard = button("Discard update", #selector(discardUpdate))
        automaticCheck = NSButton(checkboxWithTitle: "Automatically check for updates", target: self, action: #selector(toggleCheck))
        automaticInstall = NSButton(checkboxWithTitle: "Automatically install verified updates", target: self, action: #selector(toggleInstall))
        for view in [version, access, status, check, importButton, remove, automaticCheck, automaticInstall, install, discard, lastCheck] as [NSView] { stack.addArrangedSubview(view) }
        let detail = NSTextField(wrappingLabelWithString: "Updates use your private access and keep metrics on this Mac. A verified update waits until the scan ends. If installation is interrupted, open the separate Machine Monitor Recovery app.")
        detail.textColor = .secondaryLabelColor; detail.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -48).isActive = true
        stack.addArrangedSubview(detail)
        let controls = [check!, importButton!, remove!, automaticCheck!, automaticInstall!, install!, discard!]
        for i in 0..<(controls.count - 1) { controls[i].nextKeyView = controls[i + 1] }
        controls.last?.nextKeyView = controls.first; window.initialFirstResponder = check
        window.center(); refresh()
    }
    required init?(coder: NSCoder) { nil }
    private func button(_ title: String, _ action: Selector) -> NSButton {
        let button = NSButton(title: title, target: self, action: action); button.bezelStyle = .rounded; return button
    }
    func refresh() {
        guard let c = coordinator else { return }
        version.stringValue = "Machine Monitor \(c.installedVersion)"
        status.stringValue = c.status; status.setAccessibilityValue(c.status)
        access.stringValue = c.hasAccess ? "Access configured in Keychain" : "No update access configured"
        lastCheck.stringValue = c.lastCheck.map { "Last checked: " + DateFormatter.localizedString(from: $0, dateStyle: .medium, timeStyle: .short) } ?? "Not checked yet"
        let mutable = c.mutable && c.updatesEnabled
        importButton.isEnabled = mutable; remove.isEnabled = mutable && c.hasAccess
        check.isEnabled = mutable && c.hasAccess && c.phase == .idle
        automaticCheck.isEnabled = mutable; automaticInstall.isEnabled = mutable
        automaticCheck.state = c.automaticChecks ? .on : .off; automaticInstall.state = c.automaticInstall ? .on : .off
        install.isEnabled = mutable && c.phase == .ready; discard.isEnabled = mutable && c.phase == .ready
    }
    @objc private func checkNow() { coordinator?.checkForUpdates() }
    @objc private func importFile() {
        guard let window, coordinator != nil else { return }
        let picker = NSOpenPanel(); picker.canChooseDirectories = false; picker.allowsMultipleSelection = false
        picker.allowedContentTypes = [UTType(filenameExtension: "machine-monitor-access") ?? .data]
        picker.message = "Select the private access file supplied by the owner."
        picker.beginSheetModal(for: window) { [weak self] response in
            if response == .OK, let url = picker.url { self?.coordinator?.importAccessFile(url) }
        }
    }
    @objc private func removeAccess() {
        if confirm("Remove update access?", detail: "Automatic updates will stop. Monitoring remains available. You can import an access file again later.") { coordinator?.removeAccess() }
    }
    @objc private func installUpdate() { coordinator?.installAfterScan() }
    @objc private func discardUpdate() { coordinator?.discard() }
    @objc private func toggleCheck() { coordinator?.automaticChecks = automaticCheck.state == .on }
    @objc private func toggleInstall() { coordinator?.automaticInstall = automaticInstall.state == .on }
    private func confirm(_ title: String, detail: String) -> Bool {
        let alert = NSAlert(); alert.messageText = title; alert.informativeText = detail
        alert.addButton(withTitle: "Continue"); alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }
}
