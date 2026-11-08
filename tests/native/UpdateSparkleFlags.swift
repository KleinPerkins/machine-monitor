import AppKit
import Sparkle

@main struct UpdateSparkleFlags {
    static func main() throws {
        let bundle = Bundle.main
        guard let identifier = bundle.bundleIdentifier, identifier.hasPrefix("test.machine-monitor.sparkle."),
              bundle.object(forInfoDictionaryKey: "SUEnableAutomaticChecks") as? Bool == false,
              bundle.object(forInfoDictionaryKey: "SUAllowsAutomaticUpdates") as? Bool == true,
              bundle.object(forInfoDictionaryKey: "SUAutomaticallyUpdate") as? Bool == true else { fatalError("fixture bundle required") }
        defer { UserDefaults.standard.removePersistentDomain(forName: identifier) }
        _ = NSApplication.shared
        let driver = SPUStandardUserDriver(hostBundle: bundle, delegate: nil)
        let updater = SPUUpdater(hostBundle: bundle, applicationBundle: bundle, userDriver: driver, delegate: nil)
        updater.automaticallyChecksForUpdates = false
        updater.automaticallyDownloadsUpdates = true
        precondition(!updater.automaticallyChecksForUpdates)
        precondition(updater.allowsAutomaticUpdates)
        precondition(updater.automaticallyDownloadsUpdates)
        // Deliberately never starts Sparkle, activates an installer or creates a network request.
        print("SPARKLE_EFFECTIVE_FLAGS checks=false allows=true downloads=true")
    }
}
