import AppKit
import Sparkle

private final class FixtureWindow: NSWindow {
    var unoccluded = false
    override var occlusionState: NSWindow.OcclusionState { unoccluded ? [.visible] : [] }
}

@main struct UpdateVisibilityFixture {
    @MainActor static func main() {
        do { try run(); print("DEFERRED_INSTALL_VISIBILITY passed") }
        catch {
            FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
    static func require(_ condition: Bool, _ message: String) throws {
        if !condition { throw NSError(domain: "UpdateVisibilityFixture", code: 1,
                                      userInfo: [NSLocalizedDescriptionKey: message]) }
    }
    @MainActor static func run() throws {
        let bundle = Bundle.main
        guard let identifier = bundle.bundleIdentifier, identifier.hasPrefix("test.machine-monitor.visibility.")
        else { throw NSError(domain: "fixture bundle required", code: 1) }
        defer { UserDefaults.standard.removePersistentDomain(forName: identifier) }
        _ = NSApplication.shared
        NSApp.setActivationPolicy(.prohibited)
        // A window object receives the production delegate events, but is never
        // shown. Neither the collector nor Sparkle's network/installer starts.
        let window = FixtureWindow(contentRect: NSRect(x: 0, y: 0, width: 100, height: 100),
                                   styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        let session = UpdateSparkleSession(feed: URL(string: "http://127.0.0.1:1/fixture/appcast.xml")!,
                                           build: 2, bundle: bundle)
        let driver = SPUStandardUserDriver(hostBundle: bundle, delegate: nil)
        let updater = SPUUpdater(hostBundle: bundle, applicationBundle: bundle, userDriver: driver, delegate: session)
        // The unused updater argument is never started or configured; effective
        // flag persistence is covered separately by UpdateSparkleFlags.
        guard let item = SUAppcastItem(dictionary: ["title": "Fixture", "enclosure": [
            "url": "http://127.0.0.1:1/fixture/archive.zip", "sparkle:version": "2",
            "sparkle:shortVersionString": "1.1", "length": "1", "type": "application/octet-stream"]])
        else { throw NSError(domain: "fixture appcast required", code: 1) }
        try require(item.versionString == "2", "fixture version mismatch")
        var active = false, minimized = false, calls = 0
        session.isVisible = { active && !minimized && window.occlusionState.contains(.visible) }
        let coordinator = UpdateCoordinator(deferredInstallSession: session)
        let controller = MonitorApp()
        controller.window = window; controller.updates = coordinator
        let mode = CommandLine.arguments[1]
        let accepted = session.updater(updater, willInstallUpdateOnQuit: item, immediateInstallationBlock: {
            calls += 1
            if mode == "reentrant", calls < 3 { coordinator.visibilityChanged() }
        })
        try require(accepted && calls == 0, "occluded install must remain deferred")
        let activation = Notification(name: NSApplication.didBecomeActiveNotification)
        let occlusion = Notification(name: NSWindow.didChangeOcclusionStateNotification, object: window)
        if mode == "late-occlusion" {
            // Activation arrives before AppKit's later visible-window event.
            active = true; controller.applicationDidBecomeActive(activation)
            try require(calls == 0, "activation while occluded installed")
            active = false; window.unoccluded = true
            controller.windowDidChangeOcclusionState(occlusion)
            try require(calls == 0, "inactive window installed")
            window.unoccluded = false; controller.windowDidChangeOcclusionState(occlusion)
            active = true; controller.applicationDidBecomeActive(activation)
            window.unoccluded = true; controller.windowDidChangeOcclusionState(occlusion)
            try require(calls == 1, "late visible window did not resume deferred installation")
            controller.windowDidChangeOcclusionState(occlusion)
            controller.applicationDidBecomeActive(activation)
            try require(calls == 1, "duplicate visible events repeated installation")
        } else {
            active = true; window.unoccluded = true; minimized = true
            coordinator.visibilityChanged()
            try require(calls == 0, "minimized window installed")
            minimized = false; coordinator.visibilityChanged()
            coordinator.visibilityChanged()
            try require(calls == 1, "duplicate or reentrant visibility repeated installation")
        }
        try require(controller.service == nil && !controller.firstScanStarted,
                    "fixture must not launch a collector or scan")
    }
}
