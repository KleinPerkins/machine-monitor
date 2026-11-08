import AppKit
#if canImport(Sparkle)
import Sparkle

// Constructed strictly after the atomic collector lease and durable installer-pending write.
final class UpdateSparkleSession: NSObject, SPUUpdaterDelegate {
    private var updater: SPUUpdater?
    private var driver: SPUStandardUserDriver?
    private let feed: URL
    private let build: Int
    private let bundle: Bundle
    var onRecovery: (() -> Void)?
    var onActualRelaunch: (() throws -> Void)?
    var isVisible: (() -> Bool)?
    private var immediateInstall: (() -> Void)?
    init(feed: URL, build: Int, bundle: Bundle) { self.feed = feed; self.build = build; self.bundle = bundle }
    func start() throws {
        precondition(Thread.isMainThread)
        guard updater == nil,
              bundle.object(forInfoDictionaryKey: "SUEnableAutomaticChecks") as? Bool == false,
              bundle.object(forInfoDictionaryKey: "SUAllowsAutomaticUpdates") as? Bool == true,
              bundle.object(forInfoDictionaryKey: "SUAutomaticallyUpdate") as? Bool == true,
              bundle.object(forInfoDictionaryKey: "SUVerifyUpdateBeforeExtraction") as? Bool == true
        else { throw UpdateFailure.invalid("updater configuration") }
        let driver = SPUStandardUserDriver(hostBundle: bundle, delegate: nil)
        let updater = SPUUpdater(hostBundle: bundle, applicationBundle: bundle, userDriver: driver, delegate: self)
        self.driver = driver; self.updater = updater
        updater.automaticallyChecksForUpdates = false
        updater.automaticallyDownloadsUpdates = true
        guard !updater.automaticallyChecksForUpdates, updater.allowsAutomaticUpdates, updater.automaticallyDownloadsUpdates
        else { throw UpdateFailure.invalid("updater effective settings") }
        try updater.start()
        guard !updater.automaticallyChecksForUpdates, updater.allowsAutomaticUpdates, updater.automaticallyDownloadsUpdates
        else { throw UpdateFailure.invalid("updater effective settings") }
        updater.checkForUpdatesInBackground()
    }
    func feedURLString(for updater: SPUUpdater) -> String? { feed.absoluteString }
    func updater(_ updater: SPUUpdater, shouldProceedWithUpdate item: SUAppcastItem, updateCheck: SPUUpdateCheck) throws {
        guard item.versionString == String(build), item.fileURL?.scheme == "http",
              item.fileURL?.host == feed.host, item.fileURL?.port == feed.port,
              item.fileURL?.deletingLastPathComponent() == feed.deletingLastPathComponent(),
              item.fileURL?.lastPathComponent == "archive.zip" else { onRecovery?(); throw UpdateFailure.recovery }
    }
    func updater(_ updater: SPUUpdater, willInstallUpdateOnQuit item: SUAppcastItem, immediateInstallationBlock: @escaping () -> Void) -> Bool {
        guard item.versionString == String(build) else { onRecovery?(); return true }
        immediateInstall = immediateInstallationBlock
        if isVisible?() == true { DispatchQueue.main.async { [weak self] in self?.installIfVisible() } }
        return true
    }
    func installIfVisible() { if isVisible?() == true { immediateInstall?() } }
    func updaterShouldRelaunchApplication(_ updater: SPUUpdater) -> Bool { isVisible?() == true }
    func updaterWillRelaunchApplication(_ updater: SPUUpdater) {
        do { try onActualRelaunch?() } catch { onRecovery?() }
    }
    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) { onRecovery?() }
    // Cycle/session completion deliberately cannot release an install lease or resolve the journal.
}
#else
final class UpdateSparkleSession {
    var onRecovery: (() -> Void)?
    var onActualRelaunch: (() throws -> Void)?
    var isVisible: (() -> Bool)?
    init(feed: URL, build: Int, bundle: Bundle) {}
    func start() throws { throw UpdateFailure.invalid("signed updater framework unavailable") }
    func installIfVisible() {}
}
#endif
