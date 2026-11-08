import AppKit

enum UpdateInstallAdmission { case admitted(String), busy, unavailable }

final class UpdateCoordinator: NSObject {
    enum Phase: String { case disabled, idle, checking, downloading, preflighting, ready, admitting, installerPending, recoveryRequired }
    private(set) var phase: Phase = .disabled { didSet { refreshSettings(); onStateChange?() } }
    private(set) var startupDisposition: UpdateStartupDisposition = .ordinary
    private(set) var status = "Updates are unavailable in this build."
    private(set) var lastCheck: Date?
    var onStateChange: (() -> Void)?
    var admitInstall: ((String, @escaping (UpdateInstallAdmission) -> Void) -> Void)?
    var releaseInstall: ((String, @escaping (Bool) -> Void) -> Void)?
    var isVisible: (() -> Bool)?
    var allowsCollectorService: Bool { startupDisposition != .locked && startupDisposition != .recovery && phase != .installerPending && phase != .recoveryRequired && lease == nil }
    var suppressAutomaticScan: Bool { startupDisposition != .ordinary || startupReadinessPending || operation?.needsAcceptance == true || !allowsCollectorService }
    var automaticChecks: Bool {
        get { preferences?.object(forKey: "PrivateUpdateAutomaticChecks") as? Bool ?? true }
        set { guard mutable else { return }; preferences?.set(newValue, forKey: "PrivateUpdateAutomaticChecks"); refreshSettings() }
    }
    var automaticInstall: Bool {
        get { preferences?.object(forKey: "PrivateUpdateAutomaticInstall") as? Bool ?? true }
        set {
            guard mutable else { return }
            preferences?.set(newValue, forKey: "PrivateUpdateAutomaticInstall")
            if !newValue { manualInstall = false; invalidateEligibility() }
            refreshSettings()
        }
    }
    var mutable: Bool { lease == nil && phase != .installerPending && phase != .recoveryRequired && startupDisposition != .locked }
    private var configuration: UpdateConfiguration?
    private var operation: UpdateOperationState?
    private var credentials: UpdateCredentialStore?
    private var preferences: UserDefaults?
    private var access: UpdateAccess?
    private var transport: UpdateTransport?
    private let helper = UpdateHelper()
    private let generation = UpdateGeneration()
    private var manifest: UpdateManifest?
    private var verifiedArchive: UpdateVerifiedArchive?
    private var staging: URL?
    private var candidatePath: String?
    private var candidateExpandedSize: Int?
    private var bridge: UpdateLoopbackBridge?
    private var sparkle: UpdateSparkleSession?
    private var lease: String?
    private var transaction: String?
    private var manualInstall = false
    private var timer: Timer?
    private var installTimer: Timer?
    private var settings: UpdateSettingsController?
    private var startupReadinessPending = false
    private var readinessRunning = false
    private var backupPreparationInFlight = false
    private var ready = false
    private var shutDown = false

    static func bootstrap(bundle: Bundle = .main) -> UpdateCoordinator {
        let coordinator = UpdateCoordinator()
        // Source/fixture/ad-hoc bundles return before state, credential or network access.
        guard let config = UpdateConfiguration.load(bundle) else { return coordinator }
        coordinator.configuration = config
        do {
            let base = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Machine Monitor/Updates", isDirectory: true)
            let operation = try UpdateOperationState(target: bundle.bundleURL, base: base, bootID: UpdateOperationState.currentBootID())
            coordinator.operation = operation
            coordinator.startupDisposition = try operation.reconcile(build: config.currentBuild) { build in
                let expected = operation.journal?["expected"] as? [String: Any]
                let old = operation.journal?["old"] as? [String: Any]
                guard let expected, let oldBuild = old?["build"] as? Int else { throw UpdateFailure.recovery }
                let bindings = try UpdateRuntimeBindings.parse(operation.journal?["runtime_binding"])
                let manifest = try UpdateManifest.parse(JSONSerialization.data(withJSONObject: expected), configuration: bindings.admissionConfiguration(config))
                try bindings.validate(current: config.runtimeBinding(), build: build, oldBuild: oldBuild, manifest: manifest)
                let version = (expected["build"] as? Int == build ? expected["version"] : old?["version"]) as? String
                try UpdateCodeVerifier.verify(bundle.bundleURL, expectedBuild: build, expectedVersion: version)
            }
            coordinator.startupReadinessPending = operation.needsAcceptance
            if !operation.needsAcceptance { try? operation.cleanupStaging() }
            coordinator.credentials = UpdateKeychainStore(target: operation.target)
            coordinator.preferences = UserDefaults(suiteName: UpdateConfiguration.appID + ".updates." + operation.directory.lastPathComponent)
            coordinator.transport = UpdateTransport(origin: config.origin)
            coordinator.phase = .idle
            do {
                if let data = try coordinator.credentials?.read() { coordinator.access = try UpdateAccess.parse(data, origin: config.origin) }
                coordinator.status = coordinator.access == nil ? "Import an access file to enable private updates." : "Access configured."
            } catch {
                coordinator.status = "Update access is unavailable. Import an access file to resume updates. Monitoring is still available."
            }
        } catch UpdateFailure.busy {
            coordinator.startupDisposition = .locked; coordinator.phase = .recoveryRequired
            coordinator.status = UpdateFailure.busy.localizedDescription
        } catch {
            coordinator.startupDisposition = .recovery; coordinator.phase = .recoveryRequired
            coordinator.status = UpdateFailure.recovery.localizedDescription
        }
        return coordinator
    }
    var startupInstallTransactionID: String? {
        startupReadinessPending ? operation?.journal?["transaction_id"] as? String : nil
    }
    func serviceReady(startupLease: String? = nil) {
        guard let config = configuration, phase != .recoveryRequired, startupReadinessPending, !readinessRunning else { return }
        guard let startupLease, let releaseInstall else { enterRecovery(); return }
        readinessRunning = true
        do {
            try operation?.acceptReadiness(build: config.currentBuild)
            try operation?.cleanupStaging()
            releaseInstall(startupLease) { [weak self] released in
                guard let self else { return }
                guard released else { self.enterRecovery(); return }
                self.startupReadinessPending = false
                self.onStateChange?()
            }
        } catch { enterRecovery() }
    }
    func dashboardReady() {
        guard !ready, allowsCollectorService, phase != .disabled else { return }; ready = true
        if automaticChecks { checkForUpdates() }
        timer = Timer.scheduledTimer(withTimeInterval: 6 * 60 * 60, repeats: true) { [weak self] _ in
            guard let self, self.automaticChecks else { return }; self.checkForUpdates()
        }
        installTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.tryInstall() }
    }
    func visibilityChanged() { sparkle?.installIfVisible(); tryInstall() }
    func appendMenu(to menu: NSMenu) {
        menu.addItem(.separator())
        let check = menu.addItem(withTitle: "Check for Updates…", action: #selector(showCheck), keyEquivalent: "")
        check.target = self
        let settings = menu.addItem(withTitle: "Update Settings…", action: #selector(showSettings), keyEquivalent: ",")
        settings.target = self
    }
    @objc private func showCheck() { showSettings(); checkForUpdates() }
    @objc func showSettings() {
        if settings == nil { settings = UpdateSettingsController(coordinator: self) }
        settings?.showWindow(nil); settings?.window?.makeKeyAndOrderFront(nil); refreshSettings()
    }
    func checkForUpdates() {
        guard !shutDown, phase == .idle, let config = configuration, let access else { refreshSettings(); return }
        let ticket = generation.value
        set(.checking, "Checking for updates…")
        validateGrant(access, ticket: ticket) { [weak self] result in
            guard let self, self.generation.accepts(ticket) else { return }
            switch result {
            case .failure(let error): self.fail(error)
            case .success:
                do {
                    let url = try config.endpoint("/v1/apps/\(UpdateConfiguration.appID)/channels/\(config.channel)/manifest")
                    self.transport?.request(url: url, token: access.token, limit: 65_536) { [weak self] result in
                        guard let self, self.generation.accepts(ticket) else { return }
                        self.lastCheck = Date()
                        do {
                            let manifest = try UpdateManifest.parse(result.get(), configuration: config)
                            if manifest.build == config.currentBuild { self.set(.idle, "Machine Monitor is up to date."); return }
                            guard manifest.build > config.currentBuild else { throw UpdateFailure.invalid("older release") }
                            self.download(manifest, access: access, ticket: ticket)
                        } catch { self.fail(error) }
                    }
                } catch { self.fail(error) }
            }
        }
    }
    private func validateGrant(_ access: UpdateAccess, ticket: UInt64, completion: @escaping (Result<Void, Error>) -> Void) {
        guard let config = configuration else { return }
        do {
            let body = try JSONSerialization.data(withJSONObject: ["app_id": UpdateConfiguration.appID, "channel": config.channel])
            transport?.request(url: try config.endpoint("/v1/access/check"), token: access.token, body: body, limit: 16_384) { [weak self] result in
                guard let self, self.generation.accepts(ticket) else { return }
                do {
                    guard let value = try JSONSerialization.jsonObject(with: result.get()) as? [String: Any],
                          value["schema"] as? String == "machine-monitor/access-status/v1",
                          value["app_id"] as? String == UpdateConfiguration.appID, value["channel"] as? String == config.channel,
                          let expiry = value["expires_at"] as? Double, expiry > Date().timeIntervalSince1970,
                          let grant = value["grant_id"] as? String, !grant.isEmpty else { throw UpdateFailure.access }
                    completion(.success(()))
                } catch { completion(.failure(error)) }
            }
        } catch { completion(.failure(error)) }
    }
    func importAccessFile(_ url: URL) {
        guard mutable, configuration != nil else { return }
        if hasAccess {
            let alert = NSAlert(); alert.messageText = "Replace update access?"
            alert.informativeText = "Current access stays available until the new file is validated."
            alert.addButton(withTitle: "Continue"); alert.addButton(withTitle: "Cancel")
            guard alert.runModal() == .alertFirstButtonReturn else { return }
        }
        importAccess(url: url)
    }
    private func importAccess(url: URL) {
        guard mutable, let config = configuration else { return }
        do {
            let data = try UpdateAccess.readFile(url)
            let candidate = try UpdateAccess.parse(data, origin: config.origin)
            // Existing access remains intact until the new grant has validated.
            invalidateEligibility(); clearStaging()
            let ticket = generation.invalidate()
            set(.checking, "Verifying access…")
            validateGrant(candidate, ticket: ticket) { [weak self] result in
                guard let self, self.generation.accepts(ticket), self.mutable else { return }
                do {
                    try result.get(); try self.credentials?.write(data); self.access = candidate
                    self.set(.idle, "Access configured.")
                    if self.automaticChecks { self.checkForUpdates() }
                } catch { self.fail(error) }
            }
        } catch { fail(error) }
    }
    func removeAccess() {
        guard mutable else { return }
        invalidateEligibility(); clearStaging()
        do { try credentials?.remove(); access = nil; set(.idle, "Access removed. Monitoring is still available.") }
        catch { fail(error) }
    }
    func discard() {
        guard mutable else { return }
        invalidateEligibility(); clearStaging(); set(.idle, "Update discarded.")
    }
    func installAfterScan() { guard phase == .ready else { return }; manualInstall = true; tryInstall() }
    private func download(_ manifest: UpdateManifest, access: UpdateAccess, ticket: UInt64) {
        guard let config = configuration, let operation else { return }
        do {
            clearStaging()
            let directory = try operation.beginStaging(manifest: manifest); staging = directory
            let archive = directory.appendingPathComponent("archive.zip")
            self.manifest = manifest; set(.downloading, "Downloading verified release…")
            transport?.request(url: try config.endpoint(manifest.archive.path), token: access.token, limit: manifest.archive.size,
                               output: archive, expectedSize: manifest.archive.size) { [weak self] result in
                guard let self, self.generation.accepts(ticket) else { return }
                do {
                    _ = try result.get(); self.set(.preflighting, "Verifying application…")
                    // Expensive archive work never blocks AppKit or collector admission.
                    DispatchQueue.global(qos: .utility).async {
                        let verified = Result { try UpdateVerifiedArchive(url: archive, manifest: manifest, key: config.publicKey) }
                        DispatchQueue.main.async {
                            guard self.generation.accepts(ticket) else { return }
                            do { self.verifiedArchive = try verified.get(); self.preflight(manifest, archive: archive, ticket: ticket) }
                            catch { self.fail(error) }
                        }
                    }
                } catch { self.fail(error) }
            }
        } catch { fail(error) }
    }
    private var helperURL: URL? { configuration?.bundle.resourceURL?.appendingPathComponent("service/monitor-service") }
    private func preflight(_ manifest: UpdateManifest, archive: URL, ticket: UInt64) {
        guard let helperURL, let staging else { fail(UpdateFailure.invalid("preflight helper missing")); return }
        let destination = staging.appendingPathComponent("preflight", isDirectory: true)
        helper.run(executable: helperURL, mode: "--update-preflight", payload: ["archive": archive.path, "destination": destination.path, "manifest": manifest.dictionary]) { [weak self] result in
            guard let self, self.generation.accepts(ticket) else { return }
            do {
                let value = try result.get()
                guard let path = value["app_path"] as? String,
                      let expandedSize = value["expanded_size"] as? Int, expandedSize > 0,
                      URL(fileURLWithPath: path).deletingLastPathComponent().standardizedFileURL == destination.standardizedFileURL
                else { throw UpdateFailure.invalid("preflight output") }
                try UpdateCodeVerifier.verify(URL(fileURLWithPath: path), expectedBuild: manifest.build, expectedVersion: manifest.version)
                try self.verifiedArchive?.verifyUnchanged()
                self.candidatePath = path; self.candidateExpandedSize = expandedSize
                self.set(.ready, "Update ready — waiting for this scan")
                self.tryInstall()
            } catch { self.fail(error) }
        }
    }
    private func tryInstall() {
        guard !shutDown, !backupPreparationInFlight, phase == .ready, automaticInstall || manualInstall,
              isVisible?() == true, let access, let manifest, let helperURL, let operation,
              let candidatePath, let candidateExpandedSize,
              admitInstall != nil else { return }
        let ticket = generation.value
        set(.admitting, "Checking access before installation…")
        validateGrant(access, ticket: ticket) { [weak self] result in
            guard let self, self.generation.accepts(ticket) else { return }
            do {
                try result.get()
                guard self.automaticInstall || self.manualInstall else { self.set(.ready, "Update ready."); return }
                if let transaction = self.transaction, operation.journal?["phase"] as? String == "prepared" {
                    try operation.adoptPrepared(transaction: transaction, manifest: manifest, generation: ticket)
                    self.requestAdmission(transaction: transaction, manifest: manifest, ticket: ticket)
                    return
                }
                let transaction = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
                self.transaction = transaction; self.backupPreparationInFlight = true
                let preparationLock = try operation.preparationLock()
                self.helper.run(executable: helperURL, mode: "--update-recovery", payload: ["action": "prepare", "target_path": operation.target.path,
                    "manifest": manifest.dictionary, "transaction_id": transaction, "credential_generation": ticket,
                    "candidate_path": candidatePath, "expanded_size": candidateExpandedSize, "operation_lock_fd": 3], operationLock: preparationLock) { [weak self] result in
                    guard let self else { return }
                    self.backupPreparationInFlight = false
                    do {
                        let prepared = try result.get()
                        guard prepared["transaction_id"] as? String == transaction else { self.enterRecovery(); return }
                        try operation.adoptPrepared(transaction: transaction, manifest: manifest, generation: ticket)
                        guard self.generation.accepts(ticket) else { try operation.transition("cancelled"); self.transaction = nil; self.clearStaging(); return }
                        guard self.automaticInstall || self.manualInstall else { self.set(.ready, "Update ready."); return }
                        self.requestAdmission(transaction: transaction, manifest: manifest, ticket: ticket)
                    } catch {
                        if self.generation.accepts(ticket) { self.fail(error) } else { self.clearStaging() }
                    }
                }
            } catch { self.fail(error) }
        }
    }
    private func requestAdmission(transaction: String, manifest: UpdateManifest, ticket: UInt64) {
        admitInstall?(transaction) { [weak self] admission in
            guard let self else { return }
            switch admission {
            case .busy:
                if self.generation.accepts(ticket) { self.set(.ready, "Update ready — waiting for this scan") }
                return
            case .unavailable: self.enterRecovery(); return
            case .admitted(let value): self.lease = value
            }
            guard self.generation.accepts(ticket), self.automaticInstall || self.manualInstall else {
                self.abortBeforeSparkle(); return
            }
            do { try self.operation?.transition("installer-pending"); self.activateSparkle(manifest) }
            catch { self.enterRecovery() }
        }
    }
    private func activateSparkle(_ manifest: UpdateManifest) {
        guard let config = configuration, let verifiedArchive, lease != nil else { enterRecovery(); return }
        set(.installerPending, "Installing update…")
        let bridge = UpdateLoopbackBridge(archive: verifiedArchive, manifest: manifest); self.bridge = bridge
        bridge.start { [weak self] result in
            guard let self else { return }
            do {
                let session = UpdateSparkleSession(feed: try result.get(), build: manifest.build, bundle: config.bundle)
                self.sparkle = session; session.isVisible = { [weak self] in self?.isVisible?() == true }
                session.onActualRelaunch = { [weak self] in try self?.operation?.markActualRelaunch() }
                session.onRecovery = { [weak self] in self?.enterRecovery() }
                try session.start()
            } catch { self.enterRecovery() }
        }
    }
    private func abortBeforeSparkle() {
        guard sparkle == nil, let lease, let releaseInstall else { enterRecovery(); return }
        releaseInstall(lease) { [weak self] released in
            guard let self else { return }
            guard released else { self.enterRecovery(); return }
            do { try self.operation?.transition("cancelled"); self.lease = nil; self.set(.idle, "Installation cancelled before handoff.") }
            catch { self.enterRecovery() }
        }
    }
    private func invalidateEligibility() {
        generation.invalidate(); transport?.cancel(); helper.cancel()
        if !backupPreparationInFlight, operation?.journal?["phase"] as? String == "prepared" {
            do { try operation?.transition("cancelled"); transaction = nil } catch { enterRecovery(); return }
        }
        if phase == .admitting { set(.ready, "Update ready.") }
        else if [.checking, .downloading, .preflighting].contains(phase) { set(.idle, "Update cancelled.") }
    }
    private func fail(_ error: Error) {
        if lease != nil { enterRecovery(); return }
        clearStaging(); set(configuration == nil ? .disabled : .idle, (error as? UpdateFailure)?.localizedDescription ?? "Update verification failed. Monitoring is still available.")
    }
    private func enterRecovery() {
        try? operation?.transition("recovery-required")
        startupDisposition = .recovery; set(.recoveryRequired, UpdateFailure.recovery.localizedDescription)
    }
    private func set(_ phase: Phase, _ status: String) { self.status = status; self.phase = phase }
    private func clearStaging() {
        guard lease == nil else { return }
        if !backupPreparationInFlight, operation?.journal?["phase"] as? String == "prepared" { try? operation?.transition("cancelled") }
        verifiedArchive = nil; manifest = nil; transaction = nil; manualInstall = false
        candidatePath = nil; candidateExpandedSize = nil
        if !backupPreparationInFlight { try? operation?.cleanupStaging(); staging = nil }
    }
    func shutdown() {
        shutDown = true; timer?.invalidate(); installTimer?.invalidate(); generation.invalidate()
        transport?.close(); helper.cancel()
        // Keep the admitted descriptor bridge alive until application termination. Never mark
        // cycle/session completion as proof the external installer stopped.
        if lease == nil { bridge?.stop(); clearStaging() }
    }
    private func refreshSettings() { settings?.refresh() }
    var installedVersion: String { configuration.map { "\($0.version) (\($0.currentBuild))" } ?? "Source build" }
    var hasAccess: Bool { access != nil }
    var updatesEnabled: Bool { configuration != nil && phase != .recoveryRequired }
}
