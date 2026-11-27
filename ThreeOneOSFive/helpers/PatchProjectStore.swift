import CryptoKit
import Foundation

enum VesperDashDigest {
    static func hex(_ data: Data) -> String {
        CryptoKit.SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

enum RemotePackageVault {
    private struct Payload: Codable {
        var packages: [String: Data]
    }

    private static let lock = NSRecursiveLock()
    private static let magic = Data("VSPRVLT1".utf8)

    static func load(for remote: RemotePatch) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        let url = try PatchProjectLibrary.remotePackageVaultURL()
        guard FileManager.default.fileExists(atPath: url.path),
              let keyData = try PatchKeyStore.remoteVaultEncryptionKey(createIfMissing: false) else {
            return nil
        }
        let payload = try readPayload(at: url, keyData: keyData)
        guard let data = payload.packages[cacheKey(for: remote)],
              VesperDashDigest.hex(data).caseInsensitiveCompare(remote.sha256) == .orderedSame else {
            return nil
        }
        return data
    }

    static func store(_ data: Data, for remote: RemotePatch) throws {
        guard VesperDashDigest.hex(data).caseInsensitiveCompare(remote.sha256) == .orderedSame else {
            throw PatchPackageError.remoteImportFailed
        }
        lock.lock()
        defer { lock.unlock() }
        let url = try PatchProjectLibrary.remotePackageVaultURL()
        guard let keyData = try PatchKeyStore.remoteVaultEncryptionKey() else {
            throw PatchPackageError.keychainFailed
        }
        var packages: [String: Data]
        if FileManager.default.fileExists(atPath: url.path) {
            packages = (try? readPayload(at: url, keyData: keyData).packages) ?? [:]
        } else {
            packages = [:]
        }
        packages[cacheKey(for: remote)] = data
        try writePayload(Payload(packages: packages), to: url, keyData: keyData)
    }

    static func prune(keeping remotes: [RemotePatch]) throws {
        lock.lock()
        defer { lock.unlock() }
        let url = try PatchProjectLibrary.remotePackageVaultURL()
        guard FileManager.default.fileExists(atPath: url.path),
              let keyData = try PatchKeyStore.remoteVaultEncryptionKey(createIfMissing: false) else {
            return
        }
        let keep = Set(remotes.map { cacheKey(for: $0) })
        let oldPayload = try readPayload(at: url, keyData: keyData)
        let retained = oldPayload.packages.filter { keep.contains($0.key) }
        guard retained.count != oldPayload.packages.count else { return }
        if retained.isEmpty {
            try FileManager.default.removeItem(at: url)
        } else {
            try writePayload(Payload(packages: retained), to: url, keyData: keyData)
        }
    }

    private static func cacheKey(for remote: RemotePatch) -> String {
        VesperDashDigest.hex(Data("\(remote.bundle_id.lowercased())|\(remote.sha256.lowercased())".utf8))
    }

    private static func readPayload(at url: URL, keyData: Data) throws -> Payload {
        let encryptedFile = try Data(contentsOf: url, options: .mappedIfSafe)
        guard encryptedFile.starts(with: magic) else { throw PatchPackageError.invalidProject }
        let combined = encryptedFile.dropFirst(magic.count)
        let sealedBox = try AES.GCM.SealedBox(combined: Data(combined))
        let clearData = try AES.GCM.open(sealedBox, using: SymmetricKey(data: keyData))
        return try PropertyListDecoder().decode(Payload.self, from: clearData)
    }

    private static func writePayload(_ payload: Payload, to url: URL, keyData: Data) throws {
        let clearData = try PropertyListEncoder().encode(payload)
        let sealedBox = try AES.GCM.seal(clearData, using: SymmetricKey(data: keyData))
        guard let combined = sealedBox.combined else { throw PatchPackageError.remoteImportFailed }
        var encryptedFile = magic
        encryptedFile.append(combined)
        try encryptedFile.write(to: url, options: [.atomic, .completeFileProtection])
    }
}

struct PatchStoreAlert: Identifiable {
    let id = UUID()
    let titleKey: String
    let messageKey: String
    var messageArgument: String?

    init(titleKey: String, messageKey: String, messageArgument: String? = nil) {
        self.titleKey = titleKey
        self.messageKey = messageKey
        self.messageArgument = messageArgument
    }

    func message(language: AppLanguage) -> String {
        if let messageArgument {
            return language.text(messageKey, messageArgument)
        }
        return language.text(messageKey)
    }
}

@MainActor
final class PatchProjectStore: ObservableObject {
    private static let initialSyncCompletedKey = "vesperdash.initialSyncCompleted.v6"
    private static let authoritativeResetKey = "vesperdash.authoritativeReset.v4"
    private static let remoteEntriesKey = "vesperdash.remoteEntries.v3"
    private static let remoteCategoriesKey = "vesperdash.remoteCategories.v3"
    private static let remoteImagesKey = "vesperdash.remoteImages.v3"
    private static let remoteStatusesKey = "vesperdash.remoteStatuses.v3"
    private static let remoteOrdersKey = "vesperdash.remoteOrders.v3"
    private static let remoteBundlesKey = "vesperdash.remoteBundles.v3"
    private static let remoteProjectIDsKey = "vesperdash.remoteProjectIDs.v1"
    private static let remoteTargetPathsKey = "vesperdash.remoteTargetPaths.v1"
    @Published private(set) var items: [PatchLibraryItem] = []
    @Published private(set) var isBusy = false
    @Published private(set) var hasManifestSyncError = false
    @Published private(set) var hasCompletedInitialSync = false
    @Published private(set) var isRemoteDisabled = false
    @Published private(set) var remoteSyncMessage = "REMOTE DATA: WAITING"
    @Published private(set) var remoteCategories: [String: String] = [:]
    @Published private(set) var remoteImageURLs: [String: URL] = [:]
    @Published private(set) var remoteStatusTexts: [String: String] = [:]
    @Published private(set) var remoteOrders: [String: Int] = [:]
    @Published private(set) var remoteEntries: [RemotePatch] = []
    @Published private(set) var remoteBundleIDs: [String: String] = [:]
    @Published private(set) var remoteProjectIDs: [String: String] = [:]
    @Published private(set) var remoteTargetPathsByKey: [String: [String]] = [:]
    @Published private(set) var preparingRemotePatchKeys: Set<String> = []
    @Published private(set) var preparedRemotePatchKeys: Set<String> = []
    @Published private(set) var failedRemotePatchKeys: Set<String> = []
    @Published private(set) var syncFileNames: [String] = []
    @Published private(set) var syncFinishedFileNames: Set<String> = []
    @Published private(set) var syncFailedFileNames: Set<String> = []
    @Published private(set) var syncDownloadingFileNames: Set<String> = []
    @Published private(set) var syncCurrentFile = ""
    @Published var passwordRequest: PatchPasswordRequest?
    @Published var alert: PatchStoreAlert?
    @Published var unlockErrorKey: String?
    private var digestCache: [String: String] = [:]
    private var lastManifestFingerprint = ""
    private var preparedRemoteProjects: [String: PatchProject] = [:]
    private var remotePreparationGeneration = 0

    private struct PendingUnlock {
        let data: Data
        let summary: PatchPackageSummary
        let existingURL: URL?
        let builtinRemote: RemotePatch?
    }

    private var pendingUnlock: PendingUnlock?

    init() {
        PatchProjectLibrary.removeBundledPackagesIfNeeded()
        reload()
        hasCompletedInitialSync = true
        let defaults = UserDefaults.standard
        remoteEntries = EmbeddedAimPackageVault.builtinEntries
        remoteCategories = [:]
        remoteImageURLs = [:]
        remoteStatusTexts = [:]
        remoteOrders = [:]
        remoteBundleIDs = [:]
        remoteProjectIDs = defaults.dictionary(forKey: Self.remoteProjectIDsKey) as? [String: String] ?? [:]
        remoteTargetPathsByKey = defaults.dictionary(forKey: Self.remoteTargetPathsKey) as? [String: [String]] ?? [:]
    }

    func reload() {
        digestCache = [:]
        items = PatchProjectLibrary.load()
    }

    /// Reconcile bundled resources with Application Support after an app
    /// upgrade, then rebuild the in-memory package list.
    func refreshBundledPackages() {
        // Refresh the local package catalog after remote .3105 downloads.
        reload()
    }

    /// Fetch catalog metadata only. Package payloads are fetched by the user's
    /// explicit INJECT action and are never installed as .3105 files.
    func syncVesperDash(sessionToken: String?, showCompletionAlert: Bool = true) {
        guard !isBusy, let sessionToken, !sessionToken.isEmpty else { return }
        isBusy = true
        hasManifestSyncError = false
        performAuthoritativeResetIfNeeded()
        remoteBundleIDs = [:]
        remoteSyncMessage = "REMOTE DATA: CHECKING CATALOG…"
        syncFileNames = []
        syncFinishedFileNames = []
        syncFailedFileNames = []
        syncDownloadingFileNames = []
        syncCurrentFile = "FETCHING CATALOG"

        Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }
            do {
                let manifest = try await self.fetchManifestWithRetry(sessionToken: sessionToken)
                EmbeddedAimPackageVault.tryUnlockBuiltinPackages(passwords: manifest.package_passwords ?? [])
                let catalog = manifest.all_patches ?? manifest.patches
                let fingerprint = await self.manifestFingerprint(for: manifest)
                guard await self.shouldProcessManifest(fingerprint) else {
                    return
                }
                await self.applyRemoteState(paused: manifest.global_paused)
                await self.applyRemoteEntries(catalog)
                await self.pruneDownloadedRemotePackages(catalog)
                await self.finishRemoteSync(
                    showCompletionAlert: showCompletionAlert,
                    patchCount: manifest.patches.count
                )
            } catch {
                await self.failRemoteSync()
            }
        }
    }

    private func fetchManifestWithRetry(sessionToken: String) async throws -> VesperDashManifest {
        var lastError: Error?
        for attempt in 0..<3 {
            do {
                return try await VesperDashRemoteSync.fetchManifest(sessionToken: sessionToken)
            } catch is DecodingError {
                throw PatchPackageError.remoteImportFailed
            } catch let error as ManifestHTTPError {
                throw error
            } catch {
                lastError = error
                if attempt < 2 {
                    try? await Task.sleep(nanoseconds: UInt64(250_000_000 * (attempt + 1)))
                }
            }
        }
        throw lastError ?? PatchPackageError.remoteImportFailed
    }

    func remotePatchKey(for remote: RemotePatch) -> String {
        [remote.id, remote.bundle_id.lowercased(), remote.sha256.lowercased()].joined(separator: "|")
    }

    func hasPreparedRemoteProject(for remote: RemotePatch) -> Bool {
        preparedRemotePatchKeys.contains(remotePatchKey(for: remote))
    }

    func preparedRemoteProject(for remote: RemotePatch) -> PatchProject? {
        preparedRemoteProjects[remotePatchKey(for: remote)]
    }

    func remoteProjectID(for remote: RemotePatch) -> UUID? {
        if let value = remoteProjectIDs[remotePatchKey(for: remote)],
           let uuid = UUID(uuidString: value) {
            return uuid
        }
        return EmbeddedAimPackageVault.projectID(for: remote)
    }

    func targetPaths(for remote: RemotePatch) -> [String] {
        var paths = Set<String>(remote.normalizedTargetPaths)
        let key = remotePatchKey(for: remote)
        if let saved = remoteTargetPathsByKey[key] {
            paths.formUnion(saved)
        }
        if let project = preparedRemoteProjects[key] {
            paths.formUnion(project.rules.map(\.relativePath))
        }
        if EmbeddedAimPackageVault.isBuiltin(remote) {
            paths.formUnion(EmbeddedAimPackageVault.targetRelativePaths(for: remote))
        }
        return Array(paths)
    }

    func isRemotePatchActive(_ remote: RemotePatch) -> Bool {
        if EmbeddedAimPackageVault.isBuiltin(remote) {
            if let projectID = remoteProjectID(for: remote),
               DevicePatchService.latestReceipt(
                   projectID: projectID,
                   targetBundleID: remote.bundle_id
               ) != nil {
                return true
            }
            return UserDefaults.standard.bool(forKey: "walter.builtin.active.\(remotePatchKey(for: remote))")
        }
        guard let projectID = remoteProjectID(for: remote) else { return false }
        return DevicePatchService.latestReceipt(
            projectID: projectID,
            targetBundleID: remote.bundle_id
        ) != nil
    }

    func setBuiltinPatchActive(_ remote: RemotePatch, active: Bool) {
        let key = "walter.builtin.active.\(remotePatchKey(for: remote))"
        UserDefaults.standard.set(active, forKey: key)
    }

    func rememberRemoteProject(_ remote: RemotePatch, projectID: UUID, targetPaths: [String] = []) {
        let allPaths = Array(Set(remote.normalizedTargetPaths + targetPaths))
        let relatedEntries = remoteEntries.filter {
            $0.bundle_id == remote.bundle_id &&
            $0.sha256.caseInsensitiveCompare(remote.sha256) == .orderedSame
        }
        for entry in relatedEntries {
            let entryKey = remotePatchKey(for: entry)
            remoteProjectIDs[entryKey] = projectID.uuidString
            if !allPaths.isEmpty {
                remoteTargetPathsByKey[entryKey] = allPaths
            }
        }
        let key = remotePatchKey(for: remote)
        remoteProjectIDs[key] = projectID.uuidString
        if !allPaths.isEmpty {
            remoteTargetPathsByKey[key] = allPaths
        }
        UserDefaults.standard.set(remoteProjectIDs, forKey: Self.remoteProjectIDsKey)
        UserDefaults.standard.set(remoteTargetPathsByKey, forKey: Self.remoteTargetPathsKey)
    }

    func discardRemoteProjectMapping(for remote: RemotePatch) {
        let relatedEntries = remoteEntries.filter {
            $0.bundle_id == remote.bundle_id &&
            $0.sha256.caseInsensitiveCompare(remote.sha256) == .orderedSame
        }
        for entry in relatedEntries {
            let entryKey = remotePatchKey(for: entry)
            remoteProjectIDs.removeValue(forKey: entryKey)
            remoteTargetPathsByKey.removeValue(forKey: entryKey)
        }
        let key = remotePatchKey(for: remote)
        remoteProjectIDs.removeValue(forKey: key)
        remoteTargetPathsByKey.removeValue(forKey: key)
        UserDefaults.standard.set(remoteProjectIDs, forKey: Self.remoteProjectIDsKey)
        UserDefaults.standard.set(remoteTargetPathsByKey, forKey: Self.remoteTargetPathsKey)
    }

    func finishRemoteActivation(_ remote: RemotePatch) {
        // Keep preparedRemoteProjects in memory so immediate deactivation or
        // re-activation never loses the project rules during the session.
    }

    func discardPreparedRemoteProjects() {
        remotePreparationGeneration += 1
        preparedRemoteProjects.removeAll()
        preparedRemotePatchKeys.removeAll()
    }

    func finishRemoteRestore(_ remote: RemotePatch) {
        let relatedEntries = remoteEntries.filter {
            $0.bundle_id == remote.bundle_id &&
            $0.sha256.caseInsensitiveCompare(remote.sha256) == .orderedSame
        }
        for entry in relatedEntries {
            let key = remotePatchKey(for: entry)
            remoteProjectIDs.removeValue(forKey: key)
        }
        let key = remotePatchKey(for: remote)
        remoteProjectIDs.removeValue(forKey: key)
        UserDefaults.standard.set(remoteProjectIDs, forKey: Self.remoteProjectIDsKey)
    }

    func prepareRemoteProject(
        for requested: RemotePatch,
        sessionToken: String?
    ) async throws {
        let key = remotePatchKey(for: requested)
        let generation = remotePreparationGeneration
        guard !preparingRemotePatchKeys.contains(key) else { return }
        if let builtinProject = EmbeddedAimPackageVault.resolvedProject(for: requested) {
            preparedRemoteProjects[key] = builtinProject
            preparedRemotePatchKeys.insert(key)
            failedRemotePatchKeys.remove(key)
            let projectPaths = Array(Set(builtinProject.rules.map(\.relativePath) + requested.normalizedTargetPaths))
            if !projectPaths.isEmpty {
                remoteTargetPathsByKey[key] = projectPaths
                UserDefaults.standard.set(remoteTargetPathsByKey, forKey: Self.remoteTargetPathsKey)
            }
            return
        }
        if EmbeddedAimPackageVault.isBuiltin(requested) {
            if let sessionToken, !sessionToken.isEmpty,
               let manifest = try? await VesperDashRemoteSync.fetchManifest(sessionToken: sessionToken) {
                EmbeddedAimPackageVault.tryUnlockBuiltinPackages(passwords: manifest.package_passwords ?? [])
                if let builtinProject = EmbeddedAimPackageVault.resolvedProject(for: requested) {
                    preparedRemoteProjects[key] = builtinProject
                    preparedRemotePatchKeys.insert(key)
                    failedRemotePatchKeys.remove(key)
                    let projectPaths = Array(Set(builtinProject.rules.map(\.relativePath) + requested.normalizedTargetPaths))
                    if !projectPaths.isEmpty {
                        remoteTargetPathsByKey[key] = projectPaths
                        UserDefaults.standard.set(remoteTargetPathsByKey, forKey: Self.remoteTargetPathsKey)
                    }
                    return
                }
            }
            requestBuiltinUnlock(for: requested)
            throw CancellationError()
        }
        guard let sessionToken, !sessionToken.isEmpty else {
            failedRemotePatchKeys.insert(key)
            throw PatchPackageError.remoteImportFailed
        }
        preparingRemotePatchKeys.insert(key)
        failedRemotePatchKeys.remove(key)
        defer { preparingRemotePatchKeys.remove(key) }

        do {
            let manifest = try await VesperDashRemoteSync.fetchManifest(sessionToken: sessionToken)
            guard !manifest.global_paused,
                  let remote = manifest.patches.first(where: {
                      $0.id == requested.id &&
                      $0.bundle_id == requested.bundle_id &&
                      $0.sha256.caseInsensitiveCompare(requested.sha256) == .orderedSame &&
                      $0.enabled && !$0.paused
                  }) else {
                throw PatchPackageError.remoteImportFailed
            }

            let cachedPackageData = try? await Task.detached(priority: .utility) {
                try RemotePackageVault.load(for: remote)
            }.value
            let packageData: Data
            if let cachedPackageData {
                packageData = cachedPackageData
            } else {
                let directory = FileManager.default.temporaryDirectory
                    .appendingPathComponent("vesper-inject-\(UUID().uuidString)", isDirectory: true)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: directory) }
                let configuration = URLSessionConfiguration.ephemeral
                configuration.waitsForConnectivity = true
                configuration.timeoutIntervalForRequest = 30
                configuration.timeoutIntervalForResource = 300
                configuration.allowsExpensiveNetworkAccess = true
                configuration.allowsConstrainedNetworkAccess = true
                let session = URLSession(configuration: configuration)
                defer { session.invalidateAndCancel() }
                var packageURL: URL?
                var lastDownloadError: Error?
                for attempt in 0..<3 {
                    do {
                        packageURL = try await VesperDashRemoteSync.downloadPackageFile(
                            for: remote,
                            sessionToken: sessionToken,
                            using: session,
                            into: directory
                        )
                        break
                    } catch {
                        lastDownloadError = error
                        if attempt < 2 {
                            try? await Task.sleep(nanoseconds: UInt64(300_000_000 * (attempt + 1)))
                        }
                    }
                }
                guard let packageURL else {
                    throw lastDownloadError ?? PatchPackageError.remoteImportFailed
                }
                packageData = try Data(contentsOf: packageURL, options: .mappedIfSafe)
            }
            let passwords = (manifest.package_passwords ?? []).filter { !$0.isEmpty }
            let project = try await Task.detached(priority: .userInitiated) {
                guard packageData.starts(with: Data("3105PATCH\0".utf8)),
                      VesperDashDigest.hex(packageData).caseInsensitiveCompare(remote.sha256) == .orderedSame else {
                    throw PatchPackageError.remoteImportFailed
                }
                _ = try PatchPackageCodec.inspect(packageData)
                var decoded = try? PatchPackageCodec.decode(packageData, password: nil)
                if decoded == nil {
                    for password in passwords {
                        if let candidate = try? PatchPackageCodec.decode(packageData, password: password) {
                            decoded = candidate
                            break
                        }
                    }
                }
                guard let decoded,
                      decoded.project.allBundleIdentifiers.contains(remote.bundle_id) else {
                    throw PatchPackageError.invalidPasswordOrCorruptedPackage
                }
                return decoded.project
            }.value

            guard generation == remotePreparationGeneration, !Task.isCancelled else {
                throw CancellationError()
            }

            if cachedPackageData == nil {
                do {
                    try await Task.detached(priority: .utility) {
                        try RemotePackageVault.store(packageData, for: remote)
                    }.value
                } catch {
                    log("patch: remote package cache write failed: \(error.localizedDescription)")
                }
            }

            preparedRemoteProjects[key] = project
            preparedRemotePatchKeys.insert(key)
            let projectPaths = Array(Set(project.rules.map(\.relativePath) + requested.normalizedTargetPaths))
            if !projectPaths.isEmpty {
                remoteTargetPathsByKey[key] = projectPaths
                UserDefaults.standard.set(remoteTargetPathsByKey, forKey: Self.remoteTargetPathsKey)
            }
        } catch {
            if generation == remotePreparationGeneration {
                failedRemotePatchKeys.insert(key)
            }
            throw error
        }
    }

    private func pruneDownloadedRemotePackages(_ remotes: [RemotePatch]) {
        Task.detached(priority: .utility) {
            do {
                try RemotePackageVault.prune(keeping: remotes)
            } catch {
                log("patch: remote package vault cleanup failed: \(error.localizedDescription)")
            }
        }
        var itemsToRemove: [PatchLibraryItem] = []
        var mappingsChanged = false
        var staleMappingKeys: [String] = []
        for (key, value) in remoteProjectIDs {
            guard let remote = remotes.first(where: { remotePatchKey(for: $0) == key }) else { continue }
            guard let projectID = UUID(uuidString: value) else {
                staleMappingKeys.append(key)
                continue
            }
            let hasReceipt = DevicePatchService.latestReceipt(
                projectID: projectID,
                targetBundleID: remote.bundle_id
            ) != nil
            if !hasReceipt && !preparedRemotePatchKeys.contains(key) {
                staleMappingKeys.append(key)
            }
        }
        for key in staleMappingKeys {
            remoteProjectIDs.removeValue(forKey: key)
            mappingsChanged = true
        }
        for item in items {
            let packageDigest = digest(for: item)
            guard !packageDigest.isEmpty else { continue }
            let matchingRemotes = remotes.filter {
                $0.sha256.caseInsensitiveCompare(packageDigest) == .orderedSame &&
                (item.project?.allBundleIdentifiers.contains($0.bundle_id) ?? true)
            }
            guard !matchingRemotes.isEmpty else { continue }
            for remote in matchingRemotes where DevicePatchService.latestReceipt(
                projectID: item.id,
                targetBundleID: remote.bundle_id
            ) != nil {
                remoteProjectIDs[remotePatchKey(for: remote)] = item.id.uuidString
            }
            itemsToRemove.append(item)
        }
        for item in itemsToRemove {
            do {
                try PatchProjectLibrary.removePackageFileOnly(item)
            } catch {
                log("patch: could not remove cached remote .3105: \(error)")
            }
        }
        if !itemsToRemove.isEmpty || mappingsChanged {
            UserDefaults.standard.set(remoteProjectIDs, forKey: Self.remoteProjectIDsKey)
        }
        if !itemsToRemove.isEmpty {
            reload()
        }
    }

    private func manifestFingerprint(for manifest: VesperDashManifest) -> String {
        (manifest.all_patches ?? manifest.patches).map {
            [$0.id, $0.name, $0.filename, $0.sha256, $0.bundle_id, $0.target_path,
             $0.normalizedTargetPaths.joined(separator: "\u{1F}"),
             $0.category ?? "", $0.version, $0.download_url, $0.image_url ?? "",
             $0.status_text ?? "", $0.sort_order?.description ?? "", $0.enabled.description,
             $0.paused.description].joined(separator: "|")
        }.joined(separator: "\n")
    }

    private func shouldProcessManifest(_ fingerprint: String) -> Bool {
        if lastManifestFingerprint == fingerprint && hasCompletedInitialSync {
            isBusy = false
            return false
        }
        lastManifestFingerprint = fingerprint
        return true
    }

    private func beginSyncFiles(_ names: [String]) {
        syncFileNames = names
        syncFinishedFileNames = []
        syncFailedFileNames = []
        syncDownloadingFileNames = []
    }

    private func beginSyncFile(_ name: String) {
        syncCurrentFile = name
        syncFailedFileNames.remove(name)
        syncDownloadingFileNames.remove(name)
    }

    private func setSyncDownloadActive(_ name: String, active: Bool) {
        if active {
            syncDownloadingFileNames.insert(name)
        } else {
            syncDownloadingFileNames.remove(name)
        }
    }

    private func recordSyncFailure(_ name: String) {
        syncFailedFileNames.insert(name)
    }

    private func finishSyncFile(_ name: String) {
        syncFinishedFileNames.insert(name)
        syncDownloadingFileNames.remove(name)
    }

    private func setSyncCurrentFile(_ name: String) {
        syncCurrentFile = name
    }

    private func performAuthoritativeResetIfNeeded() {
        let defaults = UserDefaults.standard
        guard !defaults.bool(forKey: Self.authoritativeResetKey) else { return }
        // Reset catalog metadata only. Package and workspace files are user data;
        // the first sync after an update must never delete them.
        remoteCategories = [:]
        remoteImageURLs = [:]
        remoteStatusTexts = [:]
        remoteOrders = [:]
        remoteBundleIDs = [:]
        remoteEntries = []
        defaults.removeObject(forKey: Self.remoteEntriesKey)
        defaults.removeObject(forKey: Self.remoteCategoriesKey)
        defaults.removeObject(forKey: Self.remoteImagesKey)
        defaults.removeObject(forKey: Self.remoteStatusesKey)
        defaults.removeObject(forKey: Self.remoteOrdersKey)
        defaults.removeObject(forKey: Self.remoteBundlesKey)
        defaults.set(false, forKey: Self.initialSyncCompletedKey)
        reload()
        defaults.set(true, forKey: Self.authoritativeResetKey)
    }

    private func finishRemoteSync(
        showCompletionAlert: Bool = true,
        patchCount: Int = 0
    ) {
        reload()
        isBusy = false
        hasCompletedInitialSync = true
        hasManifestSyncError = false
        UserDefaults.standard.set(true, forKey: Self.initialSyncCompletedKey)
        remoteSyncMessage = "REMOTE DATA: UPDATED • \(patchCount) PATCH\(patchCount == 1 ? "" : "ES")"
        if showCompletionAlert {
            alert = PatchStoreAlert(titleKey: "common.done", messageKey: "patch.imported_message")
        }
    }

    private func applyRemoteState(paused: Bool) {
        isRemoteDisabled = paused
    }

    private func applyRemoteEntries(_ entries: [RemotePatch]) {
        var seenEntries = Set<String>()
        let merged = EmbeddedAimPackageVault.builtinEntries + entries
        remoteEntries = merged.filter { entry in
            // The same .3105 payload may intentionally appear in more than
            // one tab (for example ESP and Hologram). Deduplicate only within
            // the same category and target bundle, not by digest alone.
            let key = [
                entry.id,
                entry.normalizedCategory,
                entry.bundle_id.lowercased(),
                entry.sha256.lowercased(),
                entry.normalizedTargetPaths.sorted().joined(separator: "\u{0}")
            ].joined(separator: "|")
            return seenEntries.insert(key).inserted
        }
        if let data = try? JSONEncoder().encode(remoteEntries) {
            UserDefaults.standard.set(data, forKey: Self.remoteEntriesKey)
        }
    }

    func remoteEntries(category: String, bundleID: String) -> [RemotePatch] {
        remoteEntries
            .filter {
                $0.normalizedCategory == category &&
                $0.bundle_id == bundleID &&
                (($0.enabled && !$0.paused) || remoteProjectID(for: $0) != nil)
            }
            .sorted {
                if $0.normalizedOrder != $1.normalizedOrder { return $0.normalizedOrder < $1.normalizedOrder }
                return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
            }
    }

    func localFilename(for remote: RemotePatch) -> String? {
        items.first { item in
            digest(for: item).caseInsensitiveCompare(remote.sha256) == .orderedSame
        }?.packageURL.lastPathComponent
    }

    func localItem(for packageFilename: String, targetBundleID: String) -> PatchLibraryItem? {
        let remote = remoteEntries.first(where: {
            $0.filename.caseInsensitiveCompare(packageFilename) == .orderedSame &&
            $0.bundle_id == targetBundleID
        })

        if let remote {
            if let digestMatch = items.first(where: { item in
                digest(for: item).caseInsensitiveCompare(remote.sha256) == .orderedSame
            }) {
                return digestMatch
            }
        }

        // A filename is only safe when the decoded project explicitly targets
        // this bundle. Normal and Max can legitimately share a filename.
        return items.first { item in
            guard item.packageURL.lastPathComponent.caseInsensitiveCompare(packageFilename) == .orderedSame else {
                return false
            }
            return item.project?.allBundleIdentifiers.contains(targetBundleID) == true
        }
    }

    private func digest(for item: PatchLibraryItem) -> String {
        let key = item.packageURL.standardizedFileURL.path
        if let cached = digestCache[key] { return cached }
        guard let data = try? PatchProjectLibrary.readPackage(at: item.packageURL) else { return "" }
        let value = VesperDashDigest.hex(data)
        digestCache[key] = value
        return value
    }

    func remoteCategory(for item: PatchLibraryItem) -> String {
        remoteCategories[item.packageURL.standardizedFileURL.path] ?? "aim"
    }

    func hasRemoteMetadata(for item: PatchLibraryItem) -> Bool {
        remoteCategories[item.packageURL.standardizedFileURL.path] != nil
    }

    func remoteImageURL(for item: PatchLibraryItem) -> URL? {
        remoteImageURLs[item.packageURL.standardizedFileURL.path]
    }

    func remoteStatusText(for item: PatchLibraryItem) -> String {
        let value = remoteStatusTexts[item.packageURL.standardizedFileURL.path] ?? ""
        return value.isEmpty ? "NO STATUS" : value
    }

    func remoteOrder(for item: PatchLibraryItem) -> Int {
        remoteOrders[item.packageURL.standardizedFileURL.path] ?? 1000
    }

    private func reconcileRemotePackages(metadataByDigest: [String: (category: String, imageURL: URL?, statusText: String, sortOrder: Int)]) {
        var categories: [String: String] = [:]
        var imageURLs: [String: URL] = [:]
        var statusTexts: [String: String] = [:]
        var orders: [String: Int] = [:]
        var seenDigests = Set<String>()
        for item in PatchProjectLibrary.load() {
            let digest = self.digest(for: item)
            guard !digest.isEmpty else { continue }
            if let metadata = metadataByDigest[digest], seenDigests.insert(digest).inserted {
                let path = item.packageURL.standardizedFileURL.path
                categories[path] = metadata.category
                if let imageURL = metadata.imageURL {
                    imageURLs[path] = imageURL
                }
                statusTexts[path] = metadata.statusText
                orders[path] = metadata.sortOrder
            } else {
                // Do not delete user-imported local packages during remote sync.
                // Remote packages remain cached in the local package library.
            }
        }
        remoteCategories = categories
        remoteImageURLs = imageURLs
        remoteStatusTexts = statusTexts
        remoteOrders = orders
        let defaults = UserDefaults.standard
        defaults.set(categories, forKey: Self.remoteCategoriesKey)
        defaults.set(statusTexts, forKey: Self.remoteStatusesKey)
        defaults.set(orders, forKey: Self.remoteOrdersKey)
        defaults.set(imageURLs.mapValues(\.absoluteString), forKey: Self.remoteImagesKey)
        defaults.set(remoteBundleIDs, forKey: Self.remoteBundlesKey)
    }

    private func recordRemoteBundleID(remoteBundleID: String, filename: String) {
        remoteBundleIDs[filename] = remoteBundleID
    }

    func remoteBundleID(for item: PatchLibraryItem) -> String? {
        if let bundleID = remoteBundleIDs[item.packageURL.lastPathComponent] {
            return bundleID
        }
        let digest = self.digest(for: item)
        return remoteEntries.first { $0.sha256.caseInsensitiveCompare(digest) == .orderedSame }?.bundle_id
    }

    func remoteTargetPath(for item: PatchLibraryItem, targetBundleID: String) -> String? {
        let digest = self.digest(for: item)
        let remote = remoteEntries.first(where: {
            $0.sha256.caseInsensitiveCompare(digest) == .orderedSame &&
            $0.bundle_id == targetBundleID
        }) ?? remoteEntries.first(where: {
            $0.bundle_id == targetBundleID &&
            $0.name.caseInsensitiveCompare(item.displayName) == .orderedSame
        })
        guard let remote else {
            // A package can be selected before the first catalog metadata pass
            // finishes. Recover only AIM/Magic packages here; BODY/WEAPONS must
            // keep its package target and never receive the cache_res target.
            let name = item.displayName.lowercased()
            guard name.contains("aim") || name.contains("magic") else { return nil }
            return "Documents/contentcache/Compulsory/ios/gameassetbundles/cache_res.GkLlYqzsX4AtTdE55sDMRh9s-JOI~3D"
        }

        // Legacy Hologram entries and new WEAPONS variants use the active Optional shaders asset.
        // Never inherit an old AIM/cache_res target for this category.
        if remote.normalizedCategory == "weapons" {
            return "Documents/contentcache/Optional/ios/gameassetbundles/shaders.P0K3UG2TfecMBhWMMV~2Fu8ReudIk~3D"
        }

        // Keep the old working behavior: AIM receives the exact target_path
        // currently published by the server, including its case-sensitive name.
        return remote.target_path
    }

    private func failRemoteSync() {
        isBusy = false
        hasCompletedInitialSync = true
        hasManifestSyncError = false
        if remoteEntries.isEmpty {
            remoteEntries = EmbeddedAimPackageVault.builtinEntries
        }
        remoteSyncMessage = "WALTER X CHEAT • AIM SRC READY"
    }

    func create(project: PatchProject, password: String?) {
        runOperation(successMessageKey: "patch.created_message") {
            let encoded = try PatchPackageCodec.encodeNew(project: project, password: password)
            let summary = try PatchPackageCodec.inspect(encoded.data)
            let workspace = try PatchWorkspaceService.createWorkspace(for: project)
            do {
                if summary.isPasswordProtected {
                    try PatchKeyStore.store(encoded.contentKey, for: summary)
                }
                _ = try PatchProjectLibrary.save(data: encoded.data, projectName: project.name)
            } catch {
                try? FileManager.default.removeItem(at: workspace)
                try? PatchKeyStore.delete(for: summary)
                throw error
            }
        }
    }

    func update(project: PatchProject) {
        guard let item = items.first(where: { $0.id == project.id }),
              let contentKey = item.contentKey else {
            present(.invalidProject)
            return
        }
        runOperation(successMessageKey: "patch.updated_message") {
            let original = try PatchProjectLibrary.readPackage(at: item.packageURL)
            let updated = try PatchPackageCodec.update(
                original,
                project: project,
                contentKey: contentKey
            )
            _ = try PatchProjectLibrary.save(
                data: updated,
                projectName: project.name,
                existingURL: item.packageURL
            )
        }
    }

    func importPackage(at sourceURL: URL) {
        guard !isBusy else { return }
        isBusy = true
        let hasAccess = sourceURL.startAccessingSecurityScopedResource()
        Task.detached(priority: .userInitiated) { [weak self] in
            defer {
                if hasAccess { sourceURL.stopAccessingSecurityScopedResource() }
            }
            do {
                let data = try PatchProjectLibrary.readPackage(at: sourceURL)
                let summary = try PatchPackageCodec.inspect(data)
                let existingURL = await self?.existingPackageURL(for: summary.packageID)
                if let pending = try Self.persistImportedPackage(
                    data: data,
                    summary: summary,
                    existingURL: existingURL
                ) {
                    await self?.requestPassword(pending: pending)
                } else {
                    await self?.finishOperation(successMessageKey: "patch.imported_message")
                }
            } catch let error as PatchPackageError {
                await self?.failOperation(error)
            } catch {
                await self?.failOperation(.unsupportedFormat)
            }
        }
    }

    func importPackage(from source: PatchImportSource) {
        switch source {
        case .file(let url):
            importPackage(at: url)
        case .remote(let url):
            importPackage(fromRemoteURL: url)
        case .invalid:
            present(.invalidImportLink)
        }
    }

    private func importPackage(fromRemoteURL remoteURL: URL) {
        guard !isBusy,
              PatchImportRoute.validatedRemoteURL(remoteURL) != nil else {
            if !isBusy { present(.invalidImportLink) }
            return
        }
        isBusy = true
        Task.detached(priority: .userInitiated) { [weak self] in
            do {
                let configuration = URLSessionConfiguration.ephemeral
                configuration.timeoutIntervalForRequest = 60
                configuration.timeoutIntervalForResource = 600
                let session = URLSession(configuration: configuration)
                defer { session.invalidateAndCancel() }

                let (temporaryURL, response) = try await session.download(from: remoteURL)
                defer { try? FileManager.default.removeItem(at: temporaryURL) }
                guard let response = response as? HTTPURLResponse,
                      (200..<300).contains(response.statusCode),
                      let finalURL = response.url,
                      PatchImportRoute.validatedRemoteURL(finalURL) != nil else {
                    throw PatchPackageError.remoteImportFailed
                }

                let data = try PatchProjectLibrary.readPackage(at: temporaryURL)
                let summary = try PatchPackageCodec.inspect(data)
                let existingURL = await self?.existingPackageURL(for: summary.packageID)
                if let pending = try Self.persistImportedPackage(
                    data: data,
                    summary: summary,
                    existingURL: existingURL
                ) {
                    await self?.requestPassword(pending: pending)
                } else {
                    await self?.finishOperation(successMessageKey: "patch.imported_message")
                }
            } catch let error as PatchPackageError {
                await self?.failOperation(error)
            } catch {
                await self?.failOperation(.remoteImportFailed)
            }
        }
    }

    func requestUnlock(for item: PatchLibraryItem) {
        guard item.isLocked, !isBusy else { return }
        do {
            let data = try PatchProjectLibrary.readPackage(at: item.packageURL)
            pendingUnlock = PendingUnlock(data: data, summary: item.summary, existingURL: item.packageURL, builtinRemote: nil)
            passwordRequest = PatchPasswordRequest(summary: item.summary)
        } catch let error as PatchPackageError {
            present(error)
        } catch {
            present(.unsupportedFormat)
        }
    }

    func requestBuiltinUnlock(for remote: RemotePatch) {
        guard let data = EmbeddedAimPackageVault.rawData(for: remote),
              let summary = try? PatchPackageCodec.inspect(data) else { return }
        pendingUnlock = PendingUnlock(data: data, summary: summary, existingURL: nil, builtinRemote: remote)
        passwordRequest = PatchPasswordRequest(summary: summary)
    }

    func unlock(password: String) {
        guard let pending = pendingUnlock, !isBusy else { return }
        isBusy = true
        unlockErrorKey = nil
        Task.detached(priority: .userInitiated) { [weak self] in
            do {
                let decoded = try PatchPackageCodec.decode(pending.data, password: password)
                try PatchKeyStore.store(decoded.contentKey, for: pending.summary)
                if let remote = pending.builtinRemote {
                    if let project = EmbeddedAimPackageVault.resolvedProject(for: remote) {
                        await MainActor.run {
                            guard let self else { return }
                            let key = self.remotePatchKey(for: remote)
                            self.preparedRemoteProjects[key] = project
                            self.preparedRemotePatchKeys.insert(key)
                            self.rememberRemoteProject(
                                remote,
                                projectID: project.id,
                                targetPaths: project.rules.map(\.relativePath)
                            )
                        }
                        do {
                            _ = try DevicePatchService.apply(project: project)
                        } catch {
                            log("patch: builtin unlocked project staged (\(error.localizedDescription))")
                        }
                        await MainActor.run {
                            self?.setBuiltinPatchActive(remote, active: true)
                            self?.finishRemoteActivation(remote)
                        }
                    }
                    await self?.clearPendingUnlock()
                    await self?.finishOperation(successMessageKey: "patch.unlocked_message")
                    return
                }
                do {
                    try PatchProjectLibrary.installImportedPackage(
                        data: pending.data,
                        decoded: decoded,
                        summary: pending.summary,
                        existingURL: pending.existingURL
                    )
                } catch {
                    try? PatchKeyStore.delete(for: pending.summary)
                    throw error
                }
                await self?.clearPendingUnlock()
                await self?.finishOperation(successMessageKey: "patch.unlocked_message")
            } catch let error as PatchPackageError {
                await self?.failUnlock(error)
            } catch {
                await self?.failUnlock(.invalidPasswordOrCorruptedPackage)
            }
        }
    }

    func cancelUnlock() {
        clearPendingUnlock()
        isBusy = false
    }

    func clearUnlockError() {
        unlockErrorKey = nil
    }

    func delete(_ item: PatchLibraryItem) {
        do {
            try PatchProjectLibrary.delete(item)
            reload()
        } catch {
            present(.invalidProject)
        }
    }

    func synchronizeWorkspace(projectID: UUID, reportsSuccess: Bool = false) {
        guard let item = items.first(where: { $0.id == projectID }),
              item.summary.schemaVersion >= 2,
              !isBusy else { return }
        isBusy = true
        Task.detached(priority: .userInitiated) { [weak self] in
            do {
                _ = try PatchProjectLibrary.synchronizeWorkspace(item: item)
                await self?.finishWorkspaceSynchronization(reportsSuccess: reportsSuccess)
            } catch let error as PatchPackageError {
                await self?.failOperation(error)
            } catch {
                await self?.failOperation(.invalidProject)
            }
        }
    }

    private func finishWorkspaceSynchronization(reportsSuccess: Bool) {
        reload()
        isBusy = false
        if reportsSuccess {
            alert = PatchStoreAlert(
                titleKey: "common.done",
                messageKey: "patch.workspace_synced_message"
            )
        }
    }

    private func runOperation(
        successMessageKey: String,
        operation: @escaping () throws -> Void
    ) {
        guard !isBusy else { return }
        isBusy = true
        Task.detached(priority: .userInitiated) { [weak self] in
            do {
                try operation()
                await self?.finishOperation(successMessageKey: successMessageKey)
            } catch let error as PatchPackageError {
                await self?.failOperation(error)
            } catch {
                await self?.failOperation(.invalidProject)
            }
        }
    }

    private func requestPassword(pending: PendingUnlock) {
        pendingUnlock = pending
        passwordRequest = PatchPasswordRequest(summary: pending.summary)
        isBusy = false
    }

    private func existingPackageURL(for packageID: UUID) -> URL? {
        items.first(where: { $0.id == packageID })?.packageURL
    }

    private func existingPackageURL(matchingDigest digest: String) -> URL? {
        items.first { item in
            self.digest(for: item).caseInsensitiveCompare(digest) == .orderedSame
        }?.packageURL
    }

    private nonisolated static func persistImportedPackage(
        data: Data,
        summary: PatchPackageSummary,
        existingURL: URL?
    ) throws -> PendingUnlock? {
        if let key = try PatchKeyStore.load(for: summary) {
            let decoded = try PatchPackageCodec.decode(data, contentKey: key)
            try PatchProjectLibrary.installImportedPackage(
                data: data,
                decoded: decoded,
                summary: summary,
                existingURL: existingURL
            )
            return nil
        }
        if summary.isPasswordProtected {
            return PendingUnlock(data: data, summary: summary, existingURL: existingURL, builtinRemote: nil)
        }
        let decoded = try PatchPackageCodec.decode(data, password: nil)
        try PatchProjectLibrary.installImportedPackage(
            data: data,
            decoded: decoded,
            summary: summary,
            existingURL: existingURL
        )
        return nil
    }

    private func clearPendingUnlock() {
        pendingUnlock = nil
        passwordRequest = nil
        unlockErrorKey = nil
    }

    private func finishOperation(successMessageKey: String) {
        reload()
        isBusy = false
        alert = PatchStoreAlert(titleKey: "common.done", messageKey: successMessageKey)
    }

    private func failOperation(_ error: PatchPackageError) {
        isBusy = false
        present(error)
    }

    private func failUnlock(_ error: PatchPackageError) {
        isBusy = false
        // Keep the password sheet open so the user can retry.
        // Presenting an alert while dismissing the sheet swallows the message.
        if case .invalidPasswordOrCorruptedPackage = error {
            unlockErrorKey = "patch.error.wrong_password"
        } else {
            unlockErrorKey = error.localizationKey
        }
    }

    private func present(_ error: PatchPackageError) {
        alert = PatchStoreAlert(
            titleKey: "common.failed",
            messageKey: error.localizationKey,
            messageArgument: error.localizationArgument
        )
    }
}


enum EmbeddedAimPackageVault {
    static let cuelloAntenaPackageSHA256 = "19847be877aa51eb52dd25911aa60e62a4bd308f4e23f0d26a73cb0761a1d695"
    static let cuelloAntenaTargetRelativePath = "Documents/contentcache/Compulsory/ios/gameassetbundles/avatar/assetindexer.U6Zffc4YIR3DslNj3cXvYGAqz58~3D"

    static let builtinEntries: [RemotePatch] = [
        RemotePatch(
            id: "walter-cuello-antena-normal",
            name: "CUELLO - ANTENA • FF NORMAL",
            category: "aim",
            game: "normal",
            bundle_id: "com.dts.freefireth",
            target_path: cuelloAntenaTargetRelativePath,
            target_paths: [cuelloAntenaTargetRelativePath],
            filename: "Cuello - Antena.3105",
            sha256: cuelloAntenaPackageSHA256,
            version: "1.0",
            download_url: "https://api.vesperdash.com/patches/Cuello-Antena.3105",
            image_url: nil,
            status_text: "FREE FIRE NORMAL • CUELLO - ANTENA SRC • TAP TO ACTIVATE / DEACTIVATE",
            sort_order: 1,
            enabled: true,
            paused: false
        )
    ]

    static func isBuiltin(_ remote: RemotePatch) -> Bool {
        isCuelloAntena(remote)
    }

    static func isCuelloAntena(_ remote: RemotePatch) -> Bool {
        remote.id.hasPrefix("walter-cuello-antena-") ||
        remote.sha256.caseInsensitiveCompare(cuelloAntenaPackageSHA256) == .orderedSame
    }

    static func projectID(for remote: RemotePatch) -> UUID? {
        if isCuelloAntena(remote) {
            return UUID(uuidString: "502ADD2D-9562-49C0-ACFE-A1447DB76670")
        }
        return nil
    }

    static func targetRelativePaths(for remote: RemotePatch) -> [String] {
        if isCuelloAntena(remote) {
            return [cuelloAntenaTargetRelativePath]
        }
        return remote.normalizedTargetPaths
    }

    static func rawData(for remote: RemotePatch) -> Data? {
        if isCuelloAntena(remote) { return cuelloAntenaPackageData }
        return nil
    }

    static func tryUnlockBuiltinPackages(passwords: [String]) {
        // Cuello - Antena is not password-protected.
    }

    private static let cuelloAntenaBase64Chunks: [String] = [
        "MzEwNVBBVENIAGJwbGlzdDAw1gECAwQFBgcICQoLDF1zY2hlbWFWZXJzaW9uWXBhY2thZ2VJRF8QE2lzUGFzc3dvcmRQcm90ZWN0ZWRfEBBwdWJsaWNDb250",
        "ZW50S2V5XmtleUZpbmdlcnByaW50XxAQZW5jcnlwdGVkUGF5bG9hZBABXxAkNTAyQUREMkQtOTU2Mi00OUMwLUFDRkUtQTE0NDdEQjc2NjcwCE8QIHIlTIpw",
        "rh5G6MNHfLgSjan7FZYarJiIApGJuVhMsNemTxAgFh1GyaZy+IGvfByTKRz9FBkIBlc+dvY8elPIhuX813RPEbaJMvNlxQAFMNtVKuYYhmnRoW7nAnntBOSc",
        "jabIsmkActeXdhnXThjGZaGJcLWJxZcBPOa2r/vaSFmdyMSaEq/pCYbYQej6+jp5MjDWMZGK2exPLPGkROLU2It5HZedXEJLy0STfh2Gc7UBYALDm1vSlC7g",
        "kdhkkNu08qRkSzAeJKOHCbez9naDFAn4j77UIGr7FgifwtVWh6+qBRcli5mh31LqgORsit8BKXMTBsJvMRZJyzzp9vrBHyRAPJGFwaM2xb1LFAceizK0Nms7",
        "Q9fMrW0y7lozbe6lNW38sQnT5kcqnZAEW0Vs9hA4xkKwoaPxKQFOH8/ToryjfkOaNsLE/uL4XZ+D3przzw1BehLy8XqlOrlD6Len0EzSt579+ZdIDQ0JlXk0",
        "NLNItiQxK7+lf2YYBnXMHZagTK5uWzmvUj1P23u0IQRwfNaJBxdLAmLXxxoPeGGjwN1kTNzIgao1vT8Kzh/NdFfMVa94J4cuR2Fl5xK4Wc3c6tweUTpK6/B0",
        "50rGrF7Ha5gmqYJ7Y72tLZ7sn3aPfTjmKLrxcmIuVtLk+P/j4JGTdI/fFG1bh6VxUFdg8zIZML0JZTxDUkO91Ox6eAJHCNQ++849u1+QNOxutbQE0yzCbeNy",
        "bUOnSjuUmCtkHJyIjGEsuQJXh0Eh1lOkYTr63w31KiPU5UPxu6+99HoBNONmD08r35hLsQvy8PR+DPV/Xam2eV7+wV24rAcv2PWw6EyGstFZf2pczAf4R31j",
        "t/GNEfefZ65EzuHBUL4RFMPJ8TlKMaV77D9UW4d515pW45AjFE4kTY/4t6crESO3x/d1L44ffs/FJ1geB5YkhWOVvEcveUmzrii1CyeWNmBxVewDkPS60dQP",
        "/LSVYljG/YICSt0FEUshwcA9YnAgW7zSQiCdBGLTbPyHJYo4AwvcVHRXueftCKvw/EXktnmDkzMbhGGydWg+ECUrO6I7yHyrPRfDiGpG6LVpgutuDc7Sn489",
        "IMn+6TTy8n14QUM8XjX/rjWur+EvBVitM6CqUTQYpK+u4fqTBmSLimrAJ5ZS+HH754nmppNTUh6gUcp2VMn3dxEkF5cVkEBHes+jLiy5LQ7PbUKiJKAKwj5/",
        "Lc0QqpU+RGlnGeHlq433uNwTcQYwQCrHmv7lbtM7OWeeD5G9GWlvRr33jHZJEvjGAI4VeccmlLB88lP+CeVbEBhQGW77ytIId13qVlkui7fHJQzgUtUazETU",
        "ApbOIKg742d7DPlpXc0ILF+GG4EPMEX1CVOFZiCf6GDrN7GQh/wocwhgWwsFQy6v7D/l5voldXFv036/kMTud7I6WmzNiu9BUIJH3IXAX3BswoqYD6ewjtdU",
        "tPJvIzxOave8AAA/NeQjaB2j2AWAnZh8enNMvltXWzxCtsd1FiQsITDz+28rDLQMbqoldkVsw68Orf4lU0uIc+aRiCTEfcuAhLcuEqv+hYtz0sqNl5IxeWGe",
        "h4Lg4TLK2luEibPiSfMZM2CtnE62Vhhw8uhGfRvtNUPFCDyBtzpjWowk9exTjn3eBgzh9HMqOyfeDLJDUBFAIFlP5C5yVmzsFlfmVuV3s04m/OKI2kRnL8Js",
        "QnSgtYuF/V38NU+pzhoCoRJe7XbKxImxJ1PJwSmtTENvcAvH4b83IQUZ2HWdt/xx6rdyqsirOwhjZYovB0IoBf0D80cARHbri020lgtLliC55mc6jz4lGo4c",
        "m37aTbBHvk0f+l/HBBJpp23Lx+HTXZ4yGP/dXEoVWM+tHl+4/Q3HJpn1DujSEbFSVuK0Tb1z/84Yz2Y7XguJ2Ax2gg/PY8v0Wk/BBW0/kre88RdFvC97QPPJ",
        "fsA20n17MXCnIXwNQkmhVbz7YEYkze4yzvCiPon671F0cj7sUuWEcARSoodGXTbGt1BIzlhudc1sfR0MzhBtSBX3WPjPdGzBmLCnQDlWPCbaY3bCyXiUrpLR",
        "OQ0goJsJ9Vxdz56Zr8Xdk7oemPiYp3SsZRW0pG4oYbvm6xi4yfzBu/7cvtJ8UuKGZrdzkCSkak3A3wgofE6THQbAMd6xd1ClS4ADq9QnxMqhZUbK0tzy00E/",
        "fsGvipNbBFX4hO/IYnOh7C23OZRn9iHTosyFkZLaU2Fh+WI9+1J/Eixlbtq5tVH3oOfvL70YlJQRiKndj/5EhMpLwKIONLIqkEVkEAjdQjAsTJW6GlhvBxmN",
        "QuZqXem7kwSlmipA9dxoKN8wHnmDD/1DaFXwtV0nSffk4UyCtavuQ9N5iA5YdHRcKzvlUSrHeKDePRRbzkBBs5WgzHtXaIRRv97deMFOyFamqyrLSyzXaDMX",
        "3UoC8uii9Y1slpLH64RFCXQjae0JyKyAESXfC+/BqPl6L7h5M4VIozMva7SpymTSy4w+q9U7Z5e/FhEq0kHGTpWjPyXYxn7kHVWO0S0+6CU43HS2K3vO0cQ+",
        "yTbEHTOhJIBhKp8mi9recfcXpCARi7kXqN2nVx8+2yK+TkjcticzgUG7iobj61TZHjRHtUMpbTr2ineZLocYHgpYBzPb+pUQO5GNyjXHjV49xpNaeGB4S24u",
        "ujKdy6UcPJ9zFpq8lJaAT90JcpaPrEESZxbEQ6VOmspCkh5vk0DKwlIgjEtLIUNDa42v3ywZNGOt4Ip8RJ0AXoq7w1Mn6jCp5N51yPgz3GmFXuNmf0qRiJk0",
        "tdXzvqYw3R8/HEI3P8ZO30qR7Dl4DOr9r77Nb89lTRXKANgMp7PaTrPybnJAvYf5MpLr6xvfgS82vest9iIQKwYWut04FMyczwKRdKGRUb6N28YUi5o0yZay",
        "Ade1ZvFoEdWDLRbRMT043wtn0se2jlWKlSl74MysLN65suRV0pgb4KhYa/2acXjgXX8qRgFB77SRgPtDxw2rvNj0L+QPGiUUX1SitQfgI/cB0erW14QbVGFb",
        "kV+DzQPrUUu/uNmCg/NtnX2ATc3/JJB3DiMPlhkgfovPhT0mIW/bMQCvaGZhtqVs8l+MRKibAn1NFW8clb/dS44+Si/h2AOJwb8d415MWZCULP4liWAj7Kku",
        "CRwGD12P6RP4E4xRMgBM9NBv6HzkME1llkRrXnMlMwM8gV/21QDCpDhdzX5hBWdIBG2EEWkcBIJhD5sZoA5TWGVaFn8lJ2ZqvxJbzyLZpWLngXKYNuoUghf2",
        "Bqmw/cbP9dxQDhYn0zTcLkoxG79RmLoA0g95YcXTBWRKDxvUpSgul6vxtl+Wt/M/XcpKSywCgpmIZcW+Pfz0Rul/AaZcG/7UyrrsaUfmKFKap0RwmwfcEvRh",
        "+S4Ueaz5SmjYlCvNU7bpZ0ggS21CEPf6SqgN6vmorljHIelnk5grzM2sADuDcz9npm9lVIqEc+hMhBmKN6j5ZCvPqp8Q07zgL6TJZLBSx3X1A5xFRhENfU1u",
        "oJPduRD+l2tLyKQDSvOV7QqI/+1OuEsGyIl5DoW5w4JYRxXZ7y/DtHt3oDHG1eg9EbTO6f1po4Hb0hiLExrNgOxHB+7dkF51Fez9tN/hunxg5q0OqSijUhfF",
        "HmXOgp2byCEUoM/IW/pkG2pjr1UlmYrU2WOJZBbl7UdUFtQAUCOUjrsWwF0k0ZS5lL1cP9zf3jrgiOVgLpxqFACmbDMEdhxAz7hW6iTvEotrXEmDzvJciT3N",
        "jlxByG8pTQe7Lt7j//ygjkzm14v0VRaH+y0UHrK3PM92m/+lE3QLITONbYS0Atdy7XxeuP5ocmCy2nBh/KMdhITChA88M9Sks8o8JffwFCJxa65Fkm4QSnyi",
        "hna1VMmaINKodQG/deVTYhxWXq8LTT10gH9QwpzKQ4WAJBvjajjIOYQQWTXW0SOWZGo0EUjf+MRDUKEKM1TaoQNBNNTRohNHPV+QqSzo5H2fW+ViR3miKB6N",
        "nKVGShgYWGOjbLuUCEsqXKyZkJj2wj1RSRNcfoU8F5WyVS6vhF9cT4b/ZU6wLED2UJTaCOsDQvBRByqZ0KvkvFGuk5DapddXuwBrJpSyU/w4g5qAq24cWwIi",
        "VcfDbHI4gvZ97zvPW7FrqidKELFiqOk1lnbRwi7vTYFOnOVHyRFR1cGQSIEVwtDtjdQZLTbTkUhki+tEFBbvQHCp1K5o7c9oS6PckVlvXtjFevwAS1ivi4av",
        "1Sqnb5xQ37/zJgOtpMRyLOqTnaBQIbe0VUzsDsQ0gM/DC0mtFY545E6X87cbBBryzH8jmg/6HeqQSp0X+VoVizfwGWhM83S6EEUucwbeRG6NdW2uDxbygKhb",
        "Z4hpIt67ZzEh9Cme6C3LmoY4M0066ucgEDooUt76G1CVljm5OId/m9hdruEvH1hCNoXzIroN2DHbGrsq3xrrb4dr4rj2U3drEDZJn4LABDy+4fZzcAB70ru1",
        "STfZvGet4R6957xtdliMw+YetK0Z46RcfjI4qAHHp9xOiYTYNgt3yOu/MUq8xSNLZmjJw4H5LbvT4M5w7PuIUSFmBAi2YdL7iTnUVMua7I71gx3c4MANkvgb",
        "UaOzWx/gFBtQDxvylWM9yfRtaLbWQkjCwIIkfuNX103duGNXV04fUmMhl1nKSP4tBT68QFCB7PzKxZhODbfzEQCQ+uDEdTkJ7wy1aNBn+qnCA1EqHOm+Wlg5",
        "pa7N+0F3kDZEC6mwnXChA4turkNqfKmUNRXR4ug/qcd/lTGS5LaW76S/dN5gPigvJfx5w23aEHRBXgQtu0DQHWGMLriRLLG0piweUHs22+WCx+/wutrgkRVH",
        "kvC090K3EHfNNoy7ERhce2q2uXH1B/4UPPtu17Gyt0Yxbv3lGbOwd7aAO3zq8T30DC8hmfvawdj+m0oYIeAwL6OOzRUsRpJrxKDZOPlxLIFOYlhcj3zpGchJ",
        "MbTx58PcOhMHCizGY5n9nY7vcxWCb2nCU+OByfBpUOX0CMsOhuP/QJHbyAE0Hv+NA1sdmea9X3aTqkLAwfrTP/MFU6WIsTqeuVOewLRPnBYhD1+tGdFnG7Ws",
        "kTA+9nPzR53hlUySuc3gQFLXzrT3IOOyryBRbIbNWZv3rLRIP0V4P6vqveiHEFzNShiZgIrSu28qQA6e21YrIecHDTuQj7LOkqg7WO8orBKr3GqIEGITUso6",
        "zy9eQtS41l9jZoM3sc0k4b73VbXjWf4ypyz2WpQDXJBEMBmAcOEP92eBGm846rlxmXIcEEfGyNHFKlohtgLKrAI5NILyjfLbemAaa3mnQACpy+vnX/yLo9s8",
        "cKI5L3XoPE7ejjzXPpx7zYsrESijigaclEgJ1t9zc0/IN+7D/rZJ5DPQCfW6lXbdEiQPHWQr00yN5oN8VOBTATpaB8bBYraRqg/1Ejki0LVavNBbiXJSkPH/",
        "ez/XNLvq8Z4dusIZF/udsZBnF2bzdlL98TIrwVm3BfmoWS1KkMjPqK9ulF7gO8tSB3Nw4BUQDeUfCKuHeS73vT1rfmMMG9Vf5OvMZo+PFKZkCj/lZKVnlfkd",
        "9ZT2vHFuwTS0Onqt+IZTIlFEJTkmfWx2Z3FXJd2v6/dHOtOq3yL3iSr86u8eOTSwIaGS7Z8tQP48cDeW645FngymzQafGi2eRrhLdesqrtrqS1DkrUG1q1vb",
        "0BJE1tsgN81aRRFs2CnG935486BFMxkj2F/lEFkLwr8bhkm9KVKdRZWu/DEV5/0e21VGuj9ypvVuk6j57mq7C7UcPKnZBjlbm1Z9m2DGK8Ta7ykGsX6iE1nZ",
        "ae973Gzoilz87rSqR4NjiLYPvxhtOPWqd7YpZKPpE36vt+4g+BgtOng8/8XRzDHdgT9CL1xL6Tsd3GmaJ6eo7txXdnk98kPjuczZUPwPteCdPkmsQR7KswLE",
        "xoGOEO9nz2/evVNvhO811hIXShmGMLzdze1xaR6dorNxAqXV+eOm36Zed6t8dguZIjL6NsMMSSIMHqkM0WjTBnbQoQVStRYu7Lskq82cdtvsmG36s8HslYHe",
        "/MmHnvUZyz6KZeJo7qKe4ybEjat8NcO0wiHzRjMHa3cTB2wh9k6SvR1agBvp8eBdUAp2zZa3SgH0CAm7QvSWBPfmYdcj+aR9EtMiACqujnqc3n4ATeBvprZ0",
        "JgP3QAD/XmJbhzEsRlVh69U4MbuY2qYkNbQLLhHq1TR6H5dF6jpEVVit02ZdyviGqyvdftowwDuCVEjhcyf+KuVqV6c1v/wcKnFkHNTxCI93vLjn8nKbyCmW",
        "VdF8fyZnid9HP1iPFjC18oWQsOLh7Y5fQd/MsSihBMVJ2pu/88K2/EV9sNHjWkFGmVuppPdf0NDhV2YnqMC+DvPqRKsXlg63n3w/CWFVneIncAJdK9IG2XzG",
        "PeHWc7NOMsozhXlPLyFWmj4tKJF3g0YQOivfh/tgwRrQP/kH3+M9W7BvXYOd0keolpq6TOywyvm3fq4Ja6RHfvQx0Gk4sPP3gGYa7+cfp4fQW9tk+0yMBOZz",
        "uBDGSxXHJozH7Ac2taA93I6sbiSumfUjB36jt1SXR6kA+5UayGbSs8kzDmGWO9fcZIfA+HkO2KpDJHAbxHG1SwIVJXUtSJeizwS52OhcWjuMgMcfRLyWwlDP",
        "SUOP4KAVzAogpD13uiDNzl8QUaf7Dr74f+h7t9+gRCg0XIeLOPk5ye2qIvDKJ0qRXlWKi1jYWmfAE1jzDc+8nI5XxjfprlFlI6XQMzYa7sueUEqCedv7fiE/",
        "KAt//tNWB6kTBfRd8Q5N58XQffaLNw0AGDZY2NE/TIkSdpScpk7Txb5TXvR3+xjOuU2Lw1PiM4/ISlt2jFxJFK2PNKbcMVBgnnIL107o6RLTstvTKCBZT5lr",
        "rvGcqUognxPiFNfZgIM85/d9q67db4rGvmEUr00CdJ1D+KUAcs/SAnLNlkmr9EviWBC/Tua7GeKDjIWjtZFoiXAOoJ1ZR1SDvfI6GqJCp6MMl35X/Ya4vJbB",
        "Ab6xBZg70+vt0dtefPSql5w3VQF6i2XqYnZ+TgqIzOUUTtjy3BG/zruLsI5W5E+H4w6BM4DSKDQC1A9CoZGgVsBmbNpU2MHuFbx9N4ijSd0h7sX7sch5afI7",
        "JyGMX10GMMTPex651pNzNSD5HG68NJ97tWv2yxdX7WBfEdHGd0Hro/MCz2l+iD3NZp4rW9Z9BYQgmJiDPnFkCSyOtpJI+EcNnztk4yJ8oIFtfpXmcuYevO9s",
        "0raZ6PvE0Q3+yFo+MBoy/k1vw8fIJBAemTD9QI2a+U3nYxfW7RqmJJrcJFYh8vgP4AtuvnZaRywP6LxfZUVvdTbi0xzp4RFlABArg9IaP7Z9Va8MA3tQw0/C",
        "gvkHdxKfnnayB+LXcuIWCbLgVnGUMgQF5Ch3f7pOGGgfdDGo0ZMSPCQFWvebBMH6te8m1HCNY/46QyVSwEYeCFcL4+gQ7sC3fiRziwbe0ASh2slQJPBfgs+s",
        "1AhblpP3xJ4QRypnB5BPE2z0xZc8q1l9CtaYWyVjCmhxFZG8fOAtCZSA+M4CwDc8xTRKFZs8MPBnAowz2NrK7N5GC8nmekdw91gUbQu3wUkIzkrXYm3JaMtA",
        "0NjLZOkUdeS5p8MybHZo+BhiI2iVLbgTU1h209PGA17L2JEABgFf02qPLGMScfsMhX8oq5GRVdaV7aN6Yvz0qgBbELXr+SHodkO5onYybNgSdCi+CxpPyrD4",
        "n2Y0Q+AQg83SEVBX9mWOCN/fIT+rW/H/bQBl7/Ud+eLezv3eWEJVVuJRqv3rdth+ooU/xpilFBREPwPkKiFlSLVoC/RXFq08EG/nMv4BJsoOiu9/lMJygjYV",
        "QVS6hqdluXu6D1sC99PO5yVqIbAAiVKQH855fOYlMyL41LiuNHhoiIANfMUZkmhaD+lNvbR8z/VzY5kPeA4+90WUo64T+YolcFQ/k6lMSL5+bybhjPbR2PRp",
        "H9O0Sh7Fih19TJtZwRZ12Hqp3ibYgaGQRWZ56s/i1uaW8Mdn9617jl7B25b5n8i0yB3aRwOwihce4bnTB7u/ser7d4HkcvFx99j5Sv58jJl6BPZbQVsqoBYt",
        "/xfMhurj0nhttU+Xcbu8FR6HLheYK4ZV+r5AUCnMB0algQm65PRLpxMe6DTaLZNz5BD+t9Q7nQzCrOC94wuXo2cGpeWNTMD4aQaLh3/4sp9jlJf9KAIEgQDI",
        "ms3ouxqDPiYIPSFbSUY7WQbBIwc1kR7U0gexDGJzf7Qv4L0dPwKkLoyjZfIR1NMdJU2pWhrErOpPtqCeGyy6UDsykMcrSXqsVIVY/GXqrRZq1SLTVGNnwjSA",
        "n58dZiSkr7yEThVlbzdekkUovmFg5jkW1rEWzr4DS5NszDoq/ocmKzBQkZm6DkH+JZ4l/i1A0/+mb+AJgfzq3eO6QqTTsKV+vF0QSl3GAKMabKbaYyFrvhWE",
        "88d2FdAEwrFDgSoLjVdJBjRaEVeifvAB3v/rlpvi2aj0kPRzL9e4y7F9rvFKA9VnXd26C7HrakMqlg/DvVuTG41BnS5hT73UI7ys2/R7lca03JAke7XUp42e",
        "WJ3UZmlFuuyyBWE1nLaH1Dhw8kwTiC39PIHAsMQ7V9h2r+fEEVQQkGKQ7DNX0ZJqJ6y4MUqevRrasYaSJvrbchyI3SG2el0XBZc1KqoVsLH6jRen0x0bs4Mu",
        "S8MhDr0kxBw+B5OzZZbB8pQ97vd8qnF9g/ebK9JNEHjuR4Qb+d6249vOPcXJKqiBFE7bSFfDy9UyZDeWvsqCv0rJhQmPUms0t9X1qzbTHjdOUdNx0t1aWEAg",
        "+7IaGJjVB8rxWS8oZm1s0RXORmEC2mrCvsf9srorsLMHZIJPs7lUTGo+QmLnfVPUKE/ASqlBTgzAzvp4f1z07MJsZd2ydQzfSNOOHvnUNYVGEcQBEL/l6UzB",
        "X8TKR+RTV32I3PKMXtJy1u6eDFgkamW+UDDdnaG4M6G0AOG9qnYy/GXjPi0ypyz7ENA0FhedHcN9TEg7h+fxTudzlMdBZuYXq7WtLoIw/LIbzNNey/zbIMTO",
        "4mDLnuxBsyLcGCZxMLmouIoguQ+If19yBxABDSDNbuYsYvh5moyVBzpLfz5JAEduW13Hga2llbngaIRjhOZBfSqo3RLsax8HzL8fI+aDaX8ZdpaaMTFPSoU1",
        "wA+qPwHEnF/Whh9k/ucPgMDTzkaLFIoxT2LBqo1j+UOwscjoGHNcvUpVeL2W6Pee0ZosyV4G9Dix0eTw3Q0EHjBnwLlsMozQfFTXyKht9j9qwaYTUEtBTtxG",
        "PhQ4h4rK6B0qiFcvW/LJ0yIKtLxSG0adiIHA3rUcphlRNsczP90YIp/s2PgoMAZU4yKWi/DOBHGD4JmdyKUuObzvNgmZm1+Jkp/srNkfSxUBK5Loe88YPwrG",
        "wL5bN+toGSPxe4Cck9IsyV5TyIGZd6FzQpwKfURCJ19T5xMgxETKnkb3tNlkZhE06TJYh65MGamtamJq1pOPn5PC99chOWaoR7uSL0n5ZSsp0cv8LLkbecKQ",
        "+i9ymGYtN/EEvJvJAHtZFAYMIynHwHVk2ZbwrTvgkzauDvXahbgu1Pjb6rT+4HF0QtIyg3Cy9I+ZRQkvY5IyC2FK41896svumt8RAsJIwZMYfqF4J0WNww3A",
        "elzq34+AOYjBKTb2z2LRnKTiulwXkW5+lPFO7RAd3iXF77uWtkSjy+zZHZWudJaf9AUYPH3n30sQmK6//vuYUCLbF1q6e8GkbJlP3/9mS0qvFyONcxyMHJ1R",
        "dyTbOPnCrNGyxZYWkw6SAP1iFSGe4Q1xlkFeA86DbBAY0/x1iI29iSDGRV7z/ZrMCJ4+sSzspAmUtyLDbr8ha4HzZaaO4MaBRZBrn9eUwPeadz0fq/BJwwGb",
        "h3EhrlhQsFQrVzPwPObjerPrt2jljhqEjhX0zQ55fvWJG/ESRN35YB8qlh1NDD5c/bfyKLk/ETb2ZAgiKBEy8CWVdETk3cNqpQLhVS9zqIXGQ7VDXuxKD0R7",
        "dSNuUSOFf1XCTDM775/gezMTi4lWgr7S39C6/1yxCkUi0WvKf72YtzpNvAvSR/mlk2K8U/eZqb6AucDiyxnM+T1THjDX7poffh2uJN9bF2U9T0YXTzuxUm9A",
        "Y7Et3ygJsoIrzTPnqXsnZwVyaczTIqZZhv5nfbQbJ2hMULikqSg8JzgDbIGMnptHUwiPx5S0zKbXy5qRLmTBlQm93/VIwL8zVWrj9xuN6W1Jh8PQRaUs2spr",
        "fPM1Rlrl10fz+S6oxbKLycUx/yvGT5sOWmA5GJ0Vm9ikQ+A7rUoFSZmZrRlUZ24WtjQN4o/2mMKQsQdIpd82XnNIi3NeMKxekYCbHPSuzFWOKZv//QyQ4Fw9",
        "RgPeCN4ZmfOjVNyuQaVfU4gpctsYH7JJqqgmvWe9h0gvbojwb8CtNcxdAq4enTTYFteDOhZKPf1Ey8WieJUQGBfn92rvjdzT7elK1wcA9TrFBdSXI6mdMxDe",
        "vnmAK7jJCLUK60T1S49Ht0D4Y0LVWujytm7i/nU8jGffdtVGhJlcepn27eUHO8qI94UZCPhTTqPMyLIslHO1NLE+cRZN+Pjo/gxhXFhEhBCGiODly2WgUhjz",
        "BuEE1VMx2JVvtpmLq4A8zaY52mBVP7a9O2w4nj70HAnlLJtF2V8CvQ7nsA2z8xs6kz1SCPE3jlguFqRL7SuyIeZmHyULubpF9alncrTplIr6OclgUI7J29rg",
        "jJgJHT5n9qeHEMWOwLmrki8+OOQbQt/T2pclMUTwLkB2mk+oeZ+L3z6K/lY26dCWduo78uCEN4Wi6ooaEv9jhPFFZ8+vgr0XdiKectNh8B14jEiPeKqXpzHZ",
        "kyBw5x7jkrHQJTX7J1vFv/gFBIVwZfSwfmy0zQbqkasCXqlmSx0bMN0ektWM/AZ00V187HIxUXFLcOyAtMOjkwO5uVXFYy7eiM9Km7hvTrdaly7NcLr6olrO",
        "hgVXJ7iiuIqYGqQTGDKkpbQqu3rexf8ptGwTluRC5N8RK7J/XjE4Hj5uRbBkIhPKDqOw1lUQWh2SFZtfUPJIDjfuif0x7oktoP2lNVdDFaNKj5TuRDvQk+uj",
        "Un2eQfQnvFNy2yELQ6SusuSWes8Uq8KgfPJ62+AM23ypQJ9ti4t0nJ6Tb+T/UnESxS159h3Vz7nfHnGpkUtc2vadpOA3k122ALXOzK8Wp60wp4xUEnW1DzAv",
        "zy550SpJaLkLWAVffs9B3a4C3FVGrheOU1gOKv54rs1SbTJXhGL+W60rZyp/3khjWqTg2LNuYspYC267tRgjSsXQjKBivwaEdcarczOcNwpWDjRJfkeCij0N",
        "MPxf3WItjMZWIfYlf3Oek/fCSb2d0G8NrzincoZHjes9svyLKq2ptXYlZYbYGp43gom2/t5yZp6aha+V8B5CjtNaWrnLlXlJC4lUMU0DR9mwHMU5LbsAMaGq",
        "P5hrkKOle/pciWySiqy6OasMX/12KbrwGlwYkF0n49rY350vrU4D1fpf4K1/gU6ll69enI4MK3xcWZHzlYwAzg75kVrIPivLsxyYQOcAdl3bFi0zfc6pRZxN",
        "xQzf5ESkZdEOgU5LN5OxfqyNx8sF+fqKlPGeC1RtUC3lBVCBwl4QEncfM5TuOKKov1gJugqVFktaXPjNVVqpNpiFRWYgmShhWONbuUu9451vIeQgd9GgT8Ev",
        "mTZyFanvJh4Uj5DJDwQh2yZT+KohEJn0QellF755qQqHrr9U1yRM8OKQOUu9I7mLDGgmgxSP6D2I+K8XUPDE7dVqJIkQVqEpCNHcQWfbQrD4fEJeGvIYeq2N",
        "MKyEWWF7IAA95GgJDS4xqKhHsWRx/YJl0XsMC8RXVG8uc4Jt3E3RnroPltEbwde8Eo3MTlsR/Wbw/qnJesBAm6tIVlF9/V43/ZysOrLPMJNi1LDjZkILeEJL",
        "nUr+jasQJEiU7XrZE98qsHjfRkKeclmLPCWeQ+5SsbJDr/xvbtlLR2ltKirS35BhsIu57B69EOOF96iNIBzIA98oA2iWIGw/pwXZ6W8vYOGGAZhMXuu2SYsn",
        "urrCuZhGl2jX6ech/zyuOlowx72rkBjhij5N9iEKZPUx3m6pICSH+b7QgO2n9HYv0Wn6QD8G9kCPjN9AcgpskkTkqPbdPxbyo9U+Fx+a7dUfLmtPEvNKV2ii",
        "3jeyGb71oy8nQ8r7oWgTTniffFjL3aiP0Yj7aWn/ab8C9PoS6Iy8vVArAuNC0bW8KdBmmYvWyh5oQPyTc4KbV//MMA2pCYh84D5zUpttGWmgErwh4cCzWdd7",
        "dXC4lt+M/2deDnEKBxV/G4f4ejcU25hAz7RuNN9U1wGHDjFKQy8W91RoyjgO1KWdSjtzxKCslepoPmhQcJspNqfI/A1q3CtVEaUXrHDPxjKOiBy0UQi4/rWW",
        "rT+nPNA6LdClS2SKqSkmEeHiR9rMi5fElq1mBVLaDBJbsNPNjVxrYrIGaU0PnIWhF4Nn5Fr+gVs+Fd35z0x5Owj2zCOXLXtucTU+1rsuKEOeDKsgWw8/JoTW",
        "9/I0xyh2YSpnwacZ0xQjDefSEAK6zgHdJv4uu06PVFP6kOJYYir6DTAUUGjiRRKH63PMT9GmP2IFXTOeg/zVTPzIzxlI3SRemmjR21r0H++deUPxWiBNs/wq",
        "GQtnPlWN7LBEsY59SDzcwrf3mWaZtDek1gQ/BpQLooxai46P0adC15MspmNvE8iLLqw7gLTWZVRci7yUNDftJaEJLx6VA7YgU41NGJ2cOL/PNrkhF7zCoKHS",
        "K46o2UefO4C7u/Ra+eJ7wuju+zhPV5fo9Cs/dxwUmhBXwZk0gtcS70Ik1tl/34uV6CNzNQevgRLSro9K8cbipI/gNxmeRqw7hpsRxyyHHWKseul23oku+yq1",
        "ZiZTNzDtOj8YG58YMvAt1KZyHR/4Lxfba01aIeLjmu8XN7efF5k2RApVGiu2jXiS7jj5zxJg+hq2G5I36MvBxV6EyaMnN3vz6LGfaM9Bo/X1ectm3EeHi1GP",
        "TNgEfk12RC1e+xV43N6JbR0BvDeI94EU9P5nmNGpf+XyKfPu96oTzh4SHxkrXiBTclJqFQBRkNiV3APvNUIikSC3+OqGl+Avdsv28ravd3HZ9p5F4ZZXKbix",
        "5Mx93QFXNnAp+4TZyJcYu1upDY5RmOsq8bzrirVXeYykuH3wg6npHoFeiSmXdbXEYtnphEzOmbRLFfNkEwI755A1pNzZaut/FQky2ZJy7GTJTq3pYkx5AOdL",
        "ziqo/p1mYn0V4nny0+blNvglxZh2XT6AqabhXtsQWKZYyDppDecTUPfGLwPzpsefy8SdkXRFToSbpJY1imZn2WksnXgdzrCgoTp2flDJmh/8P9I/gPIUh+tS",
        "3Y6Byi7ewXEb/pu7SEibjzlT/dyccDYw+M9+in1a9rj0HMgpVUifHxAcqGke+hQQx21afo5FPaBmaLQqcJF7yL/HnbgWfDFUIJG9TnmNYimUT56jKIHviGvo",
        "5gFu19LLJX3NGQKB7ecDqs1kqpWSNDPvVLhMXcgfswR4hjfu5PbBgHfrID7tHZBOuh2lzMjHCyoq4IGpJbEXEpDK70zvG31smBiwuXBiiaLVV8VrBsLoAQTc",
        "AUp0quqMs30EeoShAjyfpeRe3Wxclg7a35oim8GyQYkw9JC2q9LH4ywXvEng/B1isTP51UxzDU6iUT8KmjN+2dQUaLpgkMGfBYk9ZLi4GF2WJBZIYOJJo/Ak",
        "yOYjSPPdy/ohirEKLg1SPTGtBHe4MP8QQ9Eh+JEdEERTxd2TU4/BSZeAGNTkcIOpSEYyqni+EKHD0lwwT50MwVN7eNWox1w7wHfO5QxJD2VtSSiJ18wVP3we",
        "ycJGrgi3K3AHBzfLpDybWP08w/zm9fHuaFvAkAQNYVROUSIgSQjE0U3lQQ/3ph04M8Noti4ssCTQMOGsLgJZqGGTABO4rXMcFhKKi2+NZgZauJspPHPaY4wO",
        "wkRCWeIN06ptb74/cZw/KDfSdaojJkrTi762uxvfbaQ+NpiLXS12kmw9t1UBz3fH+AjCQzTZiPAeEm5OcdajSTDUaQaOs9+0T/hDSaWkN9vK7KGubxYI+yhZ",
        "tMDeHZUg1YwfsY/TWXrB1q5cC3Nw8iWWlw77BWyEBP8jroAUGoP4EBFyJCwEmLJ9WvgOWBnYvwgmplXWD+UOIba60/X10W7jTN6pdYM+IKkJOaycwWuz0xe4",
        "ZadQdyveBvPLkmhXbOtWA3kHFD1+Q7ZcAoaZJRj2rRn7CxBZNLjxuHDm4E5EOZXdpwmtf2ZbjgwAy5DRzBHZKYuZBtwz1sbImRzXOCzvenKxi7lLkKU5rQUw",
        "Jf3mYzpp6foRKrwupbE1ebSx831k2pouotggXG9OPCkdAuybsdgeeKekgaL2Z22K03nnCeAOEgiwcvzBRlk/V7GItBXi0esL7TwUxOhRrxYM5sTyZxEE3fOC",
        "+le0zc3XG2Yn+u4wpk1Sm65+gp71ldJAZf0f2RUkTUb2FRYR5Job7d9zrn8/F0RECeV6UeYeh3CgVF6q0MMBT/G+F0NqEsSobUdMriy/GF0lVd5dt1ztAV7k",
        "2kprUtKD7ykrnua8KM8fFpTqXGIU5PrrFD2XIBqpCDdbJz6LJbjZdG/NffBNJMw0hKCfO0b06kmRNe0U4ysnM580TWSHny0lWpxyoxZ6irMq/sKbBXjJjF6Q",
        "xkGy9Iq8I8knO1MwXmURNB6sJ4mJDT+nzFfxm0RQruJiWpHVFvOwyEWrfPbBEf5wyO3PV7S+2W4VbOrgkg39Ir2/WtgGXiR12820M99WtxHggfdtLsl1crcM",
        "oLzxVGLdI6dr1fMT5zvEZKD2yOKaAQiOLqjP2gJwcYpdIk/HyBI5Rz59L1a46Vf7W/5Rss8rQPeZMo2pW4+oLGsLr5vUQS/hvrNzHaMTJCjkpzbU/nPH5KLL",
        "/9VxFew6or7r45gSk+3tNrVLWg3z7s5D8DIWXxSdFNH5pYrqEjV4Eo0cIw/61xvJC4INiKSRTxJeE5nq4lm0MqnSVE2WrmaaQPQrQRKDRGeGW6R65LyFPZkC",
        "gVMbD2XeJazgYopazirGFRdCjgy0Y3XEExP6LKQvm/rnsB8+Pi3vKsI1gPnSA/T53M+h9PP0Bjk5a+pvh5DT8faPU6y/PnOm8JaORNYGmVK+1jQjkXsUnoyL",
        "2Bo7Do+M3msl8Rgr9FU3DRFF1zYnvGUbi4AEuzLK4MYSfhi8rmyynqHQqK/vnaOar7gZ9P2mHj7Zjqt0ifUG5WMW3JTMR7hvRFXuKgR2oDdVjsuT6q+PECPy",
        "ociUPuar630RZZJQzoKgIZ8QErYpRdv5mla13ueaECT0ts4LB4Gj9ZR0RIvLuDZV3xd/d+aSLOiGF0+00JmF911WqojMVptUqHqM74w1vM7WAkWGABqujcJt",
        "YgpLDOFD0d/r+U1LgQJm6LrcHp3Cgxes14diUZnmFo90xpgJ9GxMrGRaPbbG+hh+UfcOVDkfn9zCd2Pux06KIcNGtInBkP9hJcsB1d+EURFOt3By+I6B6r+4",
        "Szm4w/2dPRPdmScl6+EOXEpLpI0n+XxUyXeohXZsE9My4RuogDrfFcj8dRnCiaePFoP9P0S2jJ1CXlanfQ5idgQ66WIs7ggi9u4Mlz+lNcu7X14rvvZtpbOo",
        "Q7xabo5mty/1yjP4KhUfyzzmteuCsDI6/ABz/0slauTF6yNO0n/64cnTZLQzhWZP0T1/6QJxnRlMcIg8I4RcvpkUeS5oEd5ntI0YOU3G3KelHy193esD0YI1",
        "jD2fD7Jkx6GBoxDVKdvclKyO0d/p8QhsDP43+Eu7UcuddFzbDJuYYboxTq3L/EJbvI8nfaIzN+usSAWc2FsCSMDFli1fT4mcBWyiqfxbGBRSRFCUQds8Qemw",
        "nQt7RVNxsECXRB2Lpi17IJPRroHcwN0TQFbAmYUmJV+3U9BNAafAYMH3KCFLNJK3WMsCGJRvoPtrIn7RQrsbA1OBnA6cDRTsf91VsWcDyfMfzj1s9erG+Omx",
        "6CPYK0hM/5Sbdv1gHbZmqOLfXPhxLtjB9UgEtdIP857cW4x99r1q2HfPvb7O69HqeXIwd6UHAKusv1XBuuUjvByS0LCJVSnTt/0v4j0D8liJIBGBWuRlZ72K",
        "lfV/Rq+uaG7AlXSklqjX4om5AbGRKK0KrN/fCNzTV2MLgDYTioyc6ITDcTI40+EBFhHKpJHhhBsmusuo7K/ewTolSTpq81SSZ2vcHQVlxox/OZbn4msrBc8t",
        "pAqlWtZfitOT3vz2Fpx7D/FSt7Ats9h+c5IQKgLV8zZeUptIplFkg7Vsas6ZRgcp4JznfcbtKyraWez3Ol7lMvPONbZ6H533ZeCHSgVGslQAInBjSQ1EBhwC",
        "poaBzsR9yIn+X/k1Z8EoW99jtUI7ytYWEcUJtFcxm3eU7jMjcP009/eds0LCqd272fu2k+/eKCWpbJYUM/h/rjbfV0XIziIpg5NMxWlusXpGLAb4DLPnqze6",
        "gsOzkp4V/HcQAs28Vel8DC7s7eJnv/XpR2TqWdLfOlwxI9rLA1ESxbEymSCi6FcmCsVneDnoTC099Ixgy8qJbgAPAj6LfkbST03ZxyvF33XvwCYnH/2LbLzK",
        "Nqhyc199v7bYGhL+MZchowYQwi/KC+dQTTi/9zDU/n30gbqTOB2H2sApWP7iIoMc8R5uoix8K6wt8KcpHoKxBeESzjq/6+wNBL9PKWV68PEoyQZfMdwLX+5R",
        "D3cWgrEkTlIpCleBnq/PwkQdfB+DVgA9Eh3rvO6tcfQs+WNqfyPKW+FfpE4HZLR5QT4+W4NyQ88PZ3x9qzI8G9qBRhSevpziSlyCb73GLDjMqR7gy1wqTh6J",
        "jZmgjPBIvOGqP/4BA9JNkoJUtGs0T1Nwk2wpy5G0iEbMdC1LQiLO4WKZNvayCkO61JYQtqvlJEjSkCYJcXEO1rkqSP3KalZJfZnGctOFSIC20/0AmXybBj1N",
        "LKt1tpjwy39m1QxGZvyBEQ999qy/e1YJpm0wbX3srwZafK+7fOrVXom1GyP1WV2DliQCeM0BloJ0eqXIGvKEnkkWjTVLKWdJzgTRQoyLnK1iSCgr3ptvEL/6",
        "EY4Elf9W9O58Y3BqI58s5hKdOB0dawpf9CjsRtY1F7StISePYSubjsQON1UcffmRmwA/DP+LDyrHR09GaOfYtLfvAiV5dd2o6xCZSLFNjp7Ynb//RoWzW7M9",
        "56vxsI7VfaGotRE67BvPxgfISGCk5oQ04ksSWXpltQfoc3Q+I2HPqPMrQkni1sNVTIPydAWviW6x+1ziTkPT8w4aXJE0ex1cDOTmQhiarbs2CEnOlZqiCkmm",
        "HhptYnpRppEbs8QrADnaDM3qy3IqdkZ7synBhWRC0Zd5tywUkH40J2g6AWUBjeqGkFC1TIJeH117o7+VFIme+/Lalu2WO9wC/5PPsSzDPFNNDmy9OO7pfNpI",
        "IEboQSuy6qn3+QbqKrPCDnu+l/T0UBAUlsRdx0W243wkkUSLotxvprJLjOyTiiLqbjiP56xV67s7cHgqlVjzpChu6dg8GObflFH3SDK6lKa6C5FPHuMB0tv2",
        "iFeVvvr3UEmgCeWgy1G4/mO7SqbTLRPMGBM2za9BlA55UHcf3gnmCPj/7yykd+pv0Uhy7RAKvNO3YgY8xbLw39Nhs6XP0WSQf88JYVhJ1dcdUraXpdhnK2Xp",
        "tpG43m9IsdnErD5BV/4eudoEi2iPVq+7oKxNWAWIWKDAl/pmJdtzSL04eob3r89YdII3Jmys+rHKn5hj/CSUdhXKk8akZnQVBtiY8FKGHmM/61gYzWAQkdOu",
        "NqZlEYTt4z7wB9+vKs9waZac7z+h09aI58PNRKUnrRP7C4nINNpjnlCOBD+JJ1ibwIQSVmauzOUSAe7cKra6Ze1txIGiV5USxzyD6i85EDm4awwZSOQ116PO",
        "I0e6MMx1Lu1D0KoWLfjJQJmKkB5/4/7I/0vETCbZC9O0VppE2NNetUii2Eqy/wvaCR7aCcpIcCra9AxK+z1H6WlLoy/2ZFCAkmLixfjLN/K2IlIHK3Rgty3D",
        "z5t9DIsvXWTh4116Eh16ZUa+4KqDbedeSDi+qiwxW8BBi9i/JGeoiJ/sE9EuGVsHxnacogubriL1KFxKYM+JTpzANmvFZeGDATZ0B+ZAttVqEPYMiPI2+lgz",
        "XN7PgLW2EvDoO2Ta4H5AHzXj68fXu4UZ5rmohC5jY3ylRIh6OIHAs6FSEQb/hXsJSyZBvgSYMrG9GqnJvq9g4lfYbKGedwuRwz9G7VGyzibhSBk2DDGZbW6x",
        "zPuepQ3TCArIPmsgH4xCcXgjcU1DEJdEhOPSKCr9CTvl6EpZ7z4FdF5y3+7X8znAGU5g4Hec+WL6CRe5YJ/yovSXfTVhqcwIl+mc4QPpiynqdjOCDSZDizrn",
        "nGmULtcabYuvO+RgDxtTQR8X4xDBgezJf/2CPAHO/rPwZ/x2eEzUfIRxnYB/wwQDRpJwrhNxUqpMDpP6+umiZyZMjgntZ0khHQt11bmfdzgILyRGaPmSw/W4",
        "+AT9389++dralbDElXHYximv3NfyiRdXeCFEkpwewgkmccDxMyBx7MNX+atLZh96gmB9W40t13RX8xu2Lxd1f9e1A9ZhgvdH4qlkrq/mPc/jZFR5M9O1PSL6",
        "34pFILbBWrvpfuGXbiiPP4Q8r0fYi/ceNI6qjXZsVG5KM0I4m59DZqCTMz4oE1ONcJqtJCVTLq6YQiGJ26EX7HNmOjuFYcPUuFNoKLBj6uIfEEzxF1qnxysR",
        "vGuSxBKnzWq8SxczutJKZ3m9GmunmRLEax9sLV5gUf5o3uP0u8WUFpIvN6EibotZ6/Kd6CEiCFZV5l6YQkHFTB66RhSOUOb3FPWk6/qB+dFh4dE9JtMrsoBS",
        "LTJgtOGBm4fDpwzKpsn0cf1/pz8Q1+mdxXuj/UjcH0Ukr48CqjkufR89SH8PFj2Ht7tPt9YpZca5cJytfBoafmeBVEnKi9d7brFtct7V+QvAxgCgpy+NsxAu",
        "yE8kEnxFm+AvXXuERLPiNS0UdkumDM2oRa6R7yt0JWqQfpozBs02PDAgfgousIG4qBH+1jkO9OhaVNJF3/4H1zKlgzdwe4x1CCw8DTsYMDWiXfGR9Gx8PkGm",
        "xiqBJUUQfngdlJa/dZLat8KqGUHxZaFJa0ocC0bmRtfZzqgC3HsTqzUgM1rJpXNDoghjQy0Q8vpuRmuqcWiiZzvS3rHqXVADkuM3TN6kkA4loAgfj/yps5zQ",
        "kPwxBXMiU2hrX/QQ5hPs5D20/yh+92gZ2CrBs6r7vzFeWPcwCDda7d/omEmmBlTmv/JwBBlgMd4NZ84ocmDgFGxMCUDrMfLbcQ8bkmwIBI/PmJw30Cw+86T0",
        "TboCRJsKQx2OGSSB2vmbHdlEoHipLAaJUHM0AZn0WrBvmZDJ5E6V0yS3Z9cwSzk64uBUnHYeBXVmrXuqIhlWp2tpY5PqqZvcipydX36dLqyMxsPjwPd+MKJX",
        "hvOqmgI/s+G2P20z0SMlrbxGQXxIIDNK0XJOTXzQTafRDJl37R47EK7uwJO0KSacn88IvA5zBQtOl3BBpGJiu0OZu3bM8oM1wrRbqL90KxcbVtGCTBo5RzZR",
        "E9FH3sj5uO3vBUM6C6Vb87vebm2o+0YIVImcNXdpE3hpeNgJjxtfyehflsLkN/Z0ggVYHnM0Jr3Ik4D6Cb2RRrfsItPfI+lLdRuPeMc+yFNaR7dktn4riBJi",
        "daLEXb/Q8sbzJa72L+Mb320dtBn8mkoHIUby9FZVkmCYaEscfYgYjWLxNhOgxwabOiTvxUD9oyd7pltUQJ/3+b4345AKNR2m4YFk28S1MkFkt4S2TYXsZre5",
        "cHGsFZb8alwPJITnPRq7wkIU2jllxRcPMszGYjMc+CKkX8D5/5TEZCUpqPABvDQ/I8dqB/RQnxE6DtdeVJw7nvw1yvAalQEakmm2PwN7sNKkgMasF6EDh2T3",
        "TR04ucCW5YR7y7Woo/yEA3sMbXY4joEBz2atfZaMXykE7fjF4O1aF2nEOFTvsdQCX/RJvAqTcNiPv8Ud0sMImr6qpg276tU1G8R4kMeEjOntjMS7WW3l8hPk",
        "QJegropyjioAnRjqiVJcH0FPxYGiRQMpZekKM7xBXJOHztUK7T52naQgkDjLlgtCS+BYbi41Vo9MrTjp+BupASdlJ6dnMc8NXilyw+GF6yACR2i5ysqyd3YP",
        "7WVIIAR4k/epY3meZB8jNNMVwmzzmNPnI0SR0Dpsbsdqfki4fHij19lIsxNjdgpFj8QfF7V1h0c+bhCHfGlKv2l3C6yJqQxAVQEOHIRKZAxerl5MwXEj/jVy",
        "pWFCb9cmmKwGgt9oCq64Cg+YmSDExt1VEU+XDTlpN2fcAK4lYI96S2eE8EryUBtq9q5m7pcbhTLf8pGWQ45JviF5tOivA+CA1Eg30eUPIbNtWIp3NCEuSBce",
        "7AGTJp+QcqMymBCYpU/K8cxgQLxW6R/iD4hfNAGueQ/NB0xklZIZpvH6HUXIZhZ2qJDiuHA13cUeqO0bxiHtyKCeCMYjKqHfqHBpDH1gYjJvCqLmGwGx1Dbl",
        "lWQhpliEUpl7hdY+tMttjbuZd/E2mKLIermBvHkhdDUwHUdvM9lsv092mZS8QEtxG57XMLN8bntjJicvlj7sqJ6qibamfM6ShipHA278lvEwAKUhPvdf3o+y",
        "UbNT/Of4SjcHFWn6QySM4MaIoDDGyI9SmBYjVrCAhOMGFFlthEGedNxf/BCNuaM5dWfAzrZI3pzXJWO8078rsBX3wqDPlcgiG28HXNY+4cpwfhObBwErmb/0",
        "q/9mwofzZcPIsfx3TFcRF522DBqTuPb+lP8x2PD7Nk5jrs9Y9qKwlYNcC7hKrDjHYU5Av4BcnpD/ykDJbPY2Z0xXLPm5bRRA8Zufa85zs4LhZJ1w0taqxlUb",
        "AGxIVkLT6WvCE3Al+gRs8eaGvIDdqBNqFRfQbCrYP8/JQRZ5IjdjohmmV0pUAOqdDq9+PyEdRsc7gkAkVyk8kqirJsVENpX1lEIkklPi0/AIxMzpmOYyXyt1",
        "57ORKs5PWqP4/jJcu9Rd2OaQM/5z8XXJ/HBN39DFNVIwEKxQCtAmsqcNr99Tm1VmXRC4uJkPLC8WtHedxv29F74PNmgi0EQN14sdqbDiuyd0EFZW1xv5EveT",
        "MwtyUWEnGSLUsRd1XbY3rp6bCoTdmPqE8HCPmOYNA3bEUmLniOdDxlqHd3mybMRz1qcuvVjF0uGul50qBF5Ja6N6WrqV/MKC9p1bSbdRU1nQSGpMPh/LP7Ff",
        "vPtljHE83k6eezD/Bz12M5O/9eqV9ndcPX6KmQPKJg6TzFbPsH7U02KVVjvvR0MFKyBL2OFt21LeffJ2DpocuX7y9oE4uxEY3iNufg5/ODLdtsOjyVpibJss",
        "Db3EjyprHQpfIi+6hLLqldFV4liXyN56HW90bmj7wuxe2kpn3US+tVgHOPgdn1sCk0TtFuQ7s7ap8p0VNRxA0s6GqCRHEG/4OVZzR2vIFgzE3do+lJjPgDym",
        "cu+q1x2oVIphMQOLHiBnuvHCt6ZRY5IiAqcLRrjWHPZHo0B5NY8hJlbLtxDWZsVf394DblaKwGizhe8v/SYAkbQbDw9+jY9tUeIwvVbHrhNouOquuICHCanN",
        "rRjPNwiSuv74/eXa/j+/15q1ztQrm/gsCMH+/5VaGSBIRR393eV3T+NFeiffxE4sWhXBTr+cmgt4G/fQ2Can+5dY0o055Ape3tCjiFEBvGMMnBViFv996fuE",
        "5K0rfPUykQo6GbLWDHtfQB9Pp0mx3Z6oBttqgz9+GyZ+vCswl0wbuUZ4uxvJj2tqNTnt4Fwkl5e/FaTu9OwSR/p8uuhitBU3dtc1ITpeuwTpFbRwjUryZckk",
        "B4Zz/W98kCYG1gXDrNNx1/SNt+NFvuMnsiaDuqVSAiTP3K0vHVcYFK4/KAcZ/Nqq3OJnEYzmpCZdhGfDHi0fx3mm/ZUkHRBM0Rja1Rlx9ivWa1G9EX5hZRBy",
        "03cn42vMS0thoWlWGs7dsq/tXlt1yf7Ti9iocrzMcO3xcqmbBkrgJK59ILUtaC8RITlQ3P1b5rf7zQQO0DA9sydwQtQOLkQN+7oe6RhAiHGdqaeNKbiJ/hP3",
        "pGbS7bwvoYgKdcAxN3JrSY1wez/S2Fdkl/benRdGtHB7GkOzbIAmHGOp8bwvbZEdLicyiAw1SlR9ZV6i+ixnU6D4U2uyIME9Ewz3f7MveA6qoGVumLzS2Hw0",
        "DHJm+8+k/mTlk7JuC1fESXZ1z0DvP6kr0lc77LakIoXcMSVjQPRSc7vd3sMUVxj6NlmZ9ld58QUKi+5OO88AoN7Swyizk+txBPl6hRpQ/KNb+PBP6amcbRig",
        "pycaQvLTHmupwPOkn2AsiTihwuoSdSCd3JrIAYVZ3/JZq+1BGU41zzdW5Vjozq/oXkgvaQUqd9jGUczHJNpj9iBgwgwFBRShQI5K0zmq+YwWG6RPsmonjWui",
        "9YAgIjEe56DpzFud1wMy/I/XD506PcxbOr6YcUsy5epVX7g0SHH4fAp94jxs21p+S2f6aOKuCzMLteKdexxq5pVbdX5zOplH8+kHd7F/zPns5lMr8W2LRi9P",
        "DacF270E5k+DrC4HRrRXHNYVDmIids1siokk1oLaAqldIOsGqpqZZZAlhmyjl9TPKbnnWBrddblhSOVA1VAP3xJCzZA1XrFK/BB/vhaKsnd9sQF7Tr+buz/c",
        "giK/Mh3ypxcin+ju5GnojIuRR2MXq9fHLZJQDEmRX7ygvif/Qrqi4dzwz9KTCTG/Fj8JUkSu7Xn2IoMGEX/Tykt52O3t/dRcxHHGfZQjaHfxZi6aMqw2osqs",
        "Eutt0Zeu9c+SX8+V4wnJcTiThK5FZdk8YVLNxlB5JTusViD0oBix7nWui+bNwXSEi5Ieu+CilA1MXMHb8hichxsa6GsTsMyAZNeEx337yQ8OhqluouCOW7Hx",
        "8mZqQ7b4KXyR1Zqx9GvH4EST2+kTB1EgFhNNrBR9Emif5S1nkLK1hdLfE9jDenbDzC4/gMSWTLTLelD0v37x0k/3damrLf5zPDoq+2zD6N6KPIrXZMkCNkPq",
        "s6HKAwqcN3Wzzmevf6TNJYS4GQw06ZgY0+w29n5uYLqYDDg1RaJ2tAEjQvRhqiAl1ieeelceL2yy4MldDeKoiVBNHX5HzAqX8rtDx41uBNNKToecCbGK5xFK",
        "dl67cil4fZKSEF8D8hAN2Bz56vbe9ycvbTlx7Oxzt2BPCNg3NGy+aiJoAvCkWRHzfTyVwGai42IUbsPnlpvn1+EzikB/3HN7ezedG2W4oAi6GqiYCIOy0EVZ",
        "5lgmzyC+lYkQ4lG8nkhH7G0xBjUqDOe3+bQR0o4xZYbaILVCJCoLrFdkUlEsgUVQxi3QLXmOX6jPMgOzvNYthBVYg7zOySbpCazsGwrXK8TrgLuj71gIA3qb",
        "uwNo1PkcBDjRmUzQFoPW2enH69Y7FU3JHCOFfr/HcvOq5CetXPlU1DwcWvSE7X3omAYt4DcjCw1JFS5Q1KRrlunEK9K5TjJCp+SU+wbW3YJTOmm+MmpnyGDe",
        "6i1xdFUQP/C9dsxuL65/dMfSDK93xcdsnT0V8wVoIig/YeEPvbsW9GGLPyfpdxsUqy7iPwaXQmwHSbdxg3EN9KGkckCTC1e/Vj4R+wpK1QdJnkFrOUno+t6H",
        "VeBRYCgy2cDZwliSaAljHP9MvI49Xk+E+y10azWyWMeIuIYqObVVySfiUWV3l7rptp+MU4TotG9Gnp6ji4lBufOfGt+WVyhyDmO+mpAkBBE2l/ZvSeKRXWxv",
        "Hgwf8IZJG0/D2AMniZSJ1XS+y9X845yKKwA9AijsktxuIzFG6mNX9+Z4Ka8bEU8DdleD6JBwdM0fKx4g1PqXJfXuDSxMOTmmfBhIDX+Jkp6SYa/70ZmoHiUg",
        "khno2442ufISeF5scPAFRNFiM+9QlB+OVuDuXxXtzCgyhOwBH0me9sfXeGojN6eK/0ypGBorhsQ5UT2tZox3X6ALVIL3CgjV49FzdV39arD01qrLpWti/B7U",
        "a3qdYACFE/vKGCUm+8gRolAbQ543d2pnfWldG8qKIbBxn8ch5lmfMQIHmSX7pVt02EsgdORB3TgfrrX/flcF42eeZmkuLHpU4mfrj6jYWPRc10XSKuvbWapU",
        "y4GewCH6THQitSUsBwvaLtZW15J+IDiSna2+TTxu6Q+pcjz6tftKtAJ3N6Unwk9hpdqxsrrbCAPax6hdTrc0J+WWfCscYyqn0iocS4COInodZnItCEmFS0DE",
        "O0e8x4sRteI/pROC3tJqSHG9+HCyjDo3C8nUJOVLmVRMpB3KfJ2ESU2n70TRFU/dEToh5ud5Xj2O2SpICa+8pZh9D9kV8QNz+j+MHdHeoI7+f2nOPT6lqRL7",
        "ywHUHaBzV9O6GSstexlRvyt/BOZWW0PKQCCGARtQSETwlikTdxrH+rWSXeevs1cJRA2zDYVZud9nlPlwM1s7LblUqYNJTe3oDTBm593G4StMdnO5MfuDoO6X",
        "BP10NduQXUnwBLJ4dAquzgheeQKcnOaqCouZrbzogGJzZ+4+WNMF3cGyJnAfnEu0Sbukrs+4UEKKAb/ZPFc6tXMxi2PDcYHzwextFGQ29ntzKljkV1bjzFKS",
        "EODWIjAPHNDZ+41pe4t2AY3VgqyC/4LPfIDEpv44QZE6dK6vbl2pVj8R6apUifLvGFYIqC7ad4eQDD8ph2jHOBcxqteCYtQ28K3jfkEIlAo9DO8a5ghU7Vwz",
        "xLAcExNHDqEc1WoDuDQdykGBK4Me8L2+gqiqAINLI+1Dfor2x83nVVV545yyDjW3vFe/pua361nEB/rOzqWJKCxcrVQnJLsB11FVDevdxNl0L3JXECuMUYWE",
        "r8yONEQG1gKemVlAz+CfVUyMeaHpaYdqY3l1GAbdtvVmRM55TE7QqD0e0kcN1wMxInF4vqgFeAP+SPDM7D+PWr3UWZP71cdGv4ot4iBXPLQwH5T7xrxjtkaR",
        "t18VVYuI/cQG042jU2Hp5Fa2ypw8P486U0vMsPo08zj74mwhqfWun/SVttkvFiGcZHMrYpNDgqH+BabxQK3fJL7eRT+F8Qe2Y4YkQ6uv67RN7PBCMCmF02LK",
        "2Fo8wePNP/0IslKkcT2Ii0QT24uLXLdG1L/1C17OymXJuXp6+/MoGNdNH8Ke05dBHCP5v7GLU2jnWVAb37xjX0LIo0Z6jcrvPtAG5lm8vi26N8WGAAKmu3O1",
        "gm6Ls/mWlbcrgbUU9OF2MzY/UcvwolsPFEQLQIfGviuUd//3C6xAbhYf+qrZM8nB+TQ1dvqgf+uWdRjaGfZOHdTqTV6RXcwnXUPFWT2K1KKSxDzkCuRRvqml",
        "D0vFleJYegmVSl8cruz26KndMngFeYNBIvNHHwV9ykfs+L4g5TGN4lNsAeGUtXloetr2QbQDrjsYC06lIOHMJ7nZBpbsV5XGl1wTXLaHhOwD3xdySEWROOsR",
        "D/qW/iE0Gxeo3NaxnvYQKM3aS38HO4MeOSMkBr1tHLWa46HOKQxmQLCdUJIjDcBUn8Eg5HrFN64V2Fvku82gLRtpKGCGUpvJPDxnzxHIDKg+EjydACx7Ljyi",
        "abbLtAE+/wEzNms8VX7uF0MVZPwa9RvPSwsB7flLTejvSetcFujgVpsIdmEc93xrcy8x31dDITjw0MZev7E0KZRNi4g+f1W1wpomPYltZ35TPGskILihfKQI",
        "cUqL0s53Rb8JPad/BD49a+2gtoqAIU7Wra4CvuN0KaCJnDhd60nAPK6it5sXJSj3R0OclfsqFM66v9MQwl7kAaptNEJzbAoF6JfuNRc7OcvSEpKt3fG8ohWL",
        "zFT5gIF1VG/0WVi/O4P9SqJYHwhFxB35KxmgSYOmEjBQJxQsoH9wunKBRTiz6uhYfC31a7o/XqZNcRW6ghBvnS8kerDZAeFRPAVsMq70a9231j4gdDy4nGie",
        "yBHoeQJ6Ge+l2wcR+EtLg7yrmyKPo93XZS3RDpIQh8grfUWvmqsp6WDz4aNyNLTBjvMLEJdJjD8+jSrP+H1RX3rrmBHHUUO8N4F9IAK3nIervM1O9MMSotZB",
        "p1wgXqDcG8Rvwbk+9WiFStK9ONZgomu16APKtNLqMjb2Jta+qssyy3LAUtgXSHgZkCVY4qCFD3f2mtpfTOOVmiZFI1vQ8mPyyw+zaCCvZFvFBs2PFoYO5ayS",
        "hfk6GWDpiwfybJXFv7taeLloBv2SJ4di/QjzOUVoCx2lPh7uiblyC8Unev/uVCpvZTV9ddwrmG7oz2ajPOyzVkEct12hmjkbi98SBHXP+RaBJnqtvs+6zA3i",
        "ft+1TMK7u0scO5yKqiTmZXg7qUtY/px4KV0tKwjTG2R1SJSHkdoBoIMp6agd/majMCkcidJXavWTUr1XHJeRxEMRSdx7Abam68zlIQC1LYUau6LOXn/CDXRw",
        "p0GmsHhIumucZaDaGkI/rtaBAiP5ougu3DWqBRQd1EN8zx/wXHAHWst15/G53yMohjYvDg8pTmbQeyGaB7KpcX4U7ghakYjgr7i49xU36tAcwmKkodZTJBIm",
        "3S22kVUDcSoaMFX+1qCUOAsyyAmtA0xuOyGCwi3QES14+60IDO/Ko94NP5zzEa/SFbz6Ddbb7oz+9XpTBq8/CevZVzhhUVuG8qkav5ivxMig8XvGauWMHlsF",
        "8Dk6VHGr9gdTrnIozGLJpcSx1HR8GNv6siflMbJaib0iR3YEQIIfxAl7W5T1J5j2yrx/gSwrjg7YwQlkayyo2aJObv1tGExgTv+1HITj7xEHR3+mcuso0Bas",
        "LiJybMcFAhTchB+tPqIfDDBAnpCXjssDTW3VeLrPslO7R/d1upCxj7OSIKbFjTvFptzIqlfJrr5iDO7RjFNiTWUJb18UFoKUoVgRmqhjXhhP1FBPMuEvcOc+",
        "S7CmybXm3jkE5p8yFg4VndY3UZr2kEEOqCvw7dQ7Bh4H3IHtQj8k/UrFvnhj9yNGcokWauTYNNd3kMwkjJy/CKl4EPWTEpZ4jXII16XrAc1d2EuwrqnM62dQ",
        "1nFmvc8dZx2jARmvrJFfNbSUDUIVT6lE/THFK0b8s6ihJCPtguHGb2XGXiFsNB8bmTPY8HXXQ0/FhqbbG04nEWMZYCgLqoUrf6yd2C1HmowwJNpUpZomTLSG",
        "ENrqNrXPwpj70LmOS5do88pVdpaNM4x6V95Og4HfjBhmFgw7riF2wlkxuDLG1wI2tFNg4W2kaP3poQqffTrN/J4jmL44OP4jCoaTqUeSquhvIA0P3p1ZhfoH",
        "U3hx36OfFhV3gp0osjcwqPeTiqr7IcmRapex31VnuE0/jH+1dJuE+cs/5QoNa9X81LJ1Hd19PC5Hz+ooNmJYWex/WJl1mBdFpwp6nFgbSFgj12gbJDRNvYn7",
        "u/uMCQLv3cDTjy1jW2ugeC4gxiFJKQR066I0iAutjBXzdUZWdPl/r7yYbZ4KtbPQiFxnL4Rn0apUyl0DIO/cWIEz7XGWbUlwvfvyy/3+OM4uqHgviz0WaPcd",
        "0S9h0yh2Hm4LtE2HqXO7lxnoMa+tcMToyeXDJ8i4JzM/ktalvMHEsA07WNu1wtsTNXsTDT3NGZ/w9L/KZRc+e5hVSdQMVjFA1MU4ZRGEW7WSpumGvEwZxZwJ",
        "CQJ6CLS3NHMWE/gOXCf2DXGsH2z2cQyuTMZ2JkQGPoTsYCic7wmt7au1q55EBhtLqgQ6AW0aa41ijfs5ZQvYZvK68oASc2hmpjfpBe8BTjtqVnYfm2a5VZ1N",
        "u8KGR1OGEX77C0v1pwdUHtXea/gpmfQTeOjQdH8sF7/jog0rfYV1GoNCiqHw/QvohqtDkDpNKipE4UrU8z11KKUcLgubwj28hwd3kLs7wUCJ/IaoGboRQSey",
        "YccbwXJ1sFmUv/sxLffStlNBrEwqmVyXI0YgAxyYxVgWiBxhpeB2M1oDn21I4Ny3FsImhos/haag22vF3lpLBz/bTMWUs15lWiyY3cygpTX1t96eHdF5fYgY",
        "DMAV+H59COF/o73bnsvJ9IyTnvF/Zh1wYebTxZ/kol2mywaqKuVNj1HFcdJFYaVJ/2aLYh7bsgxl5+4VsmPUOy/ygMytZS97urQZqZvP6L9snQjARqRRC7D6",
        "flhCRdKgRD+6IDOvUE71NNdjtEt0IgxEO12lXiUOIOe1qZ3ibY7jjwSdS5BKc0+Khhj4x6pMjt3Z8gaQ4ny4VapYhI8WQy/jPwEAjJSDBoZigKcuLRtswcEp",
        "eTdwEbwecU0JKCm6nt+ZJ+xQEqUJBUEdEGrGutjfsPS8iiFS5dKEDwrY1xFnDIeOdk+qBmDoAJY2hxKyDZT3L+A2DFm3OldCAQwZ+RDdlpXhi0lMkZ+oQ7gf",
        "UfWiISm9jqbT4/IglxiIgH+vfjHrxjP+ktWYcfOdOGytWLVNuYyF7YheZAuOs2j/WpwlfG4n89g3IfgCGaPzsQz0GTVGFWuazWuIH/vOwvma5MGjhcxhJEMd",
        "cCEQ5G6w+9xoiOc8lAzaEoVMWiQSy+6gSusmIaIk/j5yXlL8aUHVGrFIqQzzBOIgrwJ81F1+SbGJC77LmI74gmhSghXCTwc319QFqNFJ64Hvb78pYRaVU5gQ",
        "xXXtR4x7mxWP3oKP99bod4O4ieV409MRdlycstGnK678TNA2tupRiwmbcf3rA2qpHOWdYEgkXhhmn+H9ZmENxWmOXa5mjb2rLhnzF8Xfe6S0SlrK1BzFX8kn",
        "Qoh1uqAPo/4qSQvLg+aZ+ICsaIAeqSCfaY/doBIQt08wWrHzHYW0M/TFiSHxjmGfH0Ej3xYNwFhFn6VRpYSPJbo3EhSE+W908g9sSHfEhy85RF/R1Iqg2mo4",
        "/zGXruT1YFG0Mp6A9IaiKLGFw+gYQgsOy49SoqzMFY6GHm7E1xa2csbUI7XM2NKjdQXfKpcPkbjxgkFr1914Hf3sTSBsEf+eXZ8KBdAFYmst3Mdv1d7tZAaX",
        "99BQxptFbdazKZmzNhvlcoVp4AcDl9YiHA/HRBjtu61ZgnlNLOBjqIcdd161MC6oq6LfkvTvrljcRSx7WNsF+LD6axlgita/lQAF2jv5E/mOZgd4UZetOEPA",
        "kqQiEoeNJfqVbR+j1JdQLlSot2aOvH6wNeaS29ksIxtEzwnjo49QO11HZporqqWeU9cdqI7OBcp6sv9UJsqUd7tz7o8notB28LEnXXxHHNETkzd6/DDRnsU9",
        "XkVWJiE90S4dPikd9w77BaF/HpGCtokCzMytyZRjbgFBIXn9iFZWB0UHpgyDziS4qfFNMZ5vQ3AxkSrfieHtW/midPACSBe8yzaw3yO2DpZaknEi0uyzUE6l",
        "/ei1lqcxawmICryoBHnqXPfMQCWCiVbbvHAisCM4AUDRFTm/aPTWJXZZQlKwEnwQiNY66g8FnKpVDEa2o0DXyDVMPPnLCqof6mApQzDUlUdWdlsosmG1i39c",
        "sLVr/9NCxFt6szvbvoGqbpoQpe91r7jJ98YCJjaiRVL+VXWLrw8gMkFNsMSm4qIU1WuOui4ycVbjaimlToW/Nq3Ybz+HAGtf0kC/Q1wHrpYkyYd6BWCmmJOZ",
        "Qrwm6RsAHjv6iQziaJi06Gvg1hKGK3wExBqL/60TW//Eb06gd0td+rEHM43Gxj4ractS34zFzujqhScOaTieCA6Vwp1ANB5GUq1bm8VZ1v1nZEIzNPZePnAh",
        "+4q9I9zi3FLdxCz94mQEymcbmBOYEdwnnYWszXhY6KzJsq4D9MbfYkHBV1UtZR0WN2BQZP3LOw4ZpRl11bDX/MQ4O+UnDv06zJiDqV+8Ls774ioAuTlie37K",
        "MYq8Gz8mYLVk3u+TobNYqRJTVF7csG6BnEkv0xCLIABsN9MngC6L79qWQVZc5ERE3DABptew6uSpDJrVQe5dwPtmoojMGsFji0CmiQQIexOMd5KHyLPDJ2dm",
        "U6EIkLOYPoveG1hOIRwn3bbKhwOyyt7b5GiXBd174mwKSFTrpjoSupOA8cwnkncz6EmMgO5NITce2qRvt+yfAw0gxz8Utn+2oNaSX8n5/i0zrfH93vQs7ymq",
        "GpZs2DLvnrhgTsPiH/uqRU3OyGLiAchs2cIeB5idXLZN1x3cIemSInSlMo39l4sj5FVn4GxbT7ianUvgHyGvn8FS4sFn4xcYdd04oRWaf7RrEKlHs30opMZ0",
        "wTwaCUg6Z/Q5gUdHdg3YEBMgb0wLuxf3mZ4u9PSxbtb81EybdX+sqXlsxH/+g6bCELmdT2W8BR/QdI00H2bVlxNnaZOqud3tWs1Rs/SYXdyziOQ8NruGo6vl",
        "3zwY0hiknpBtNn6c4ISfT9RGaaDKWd1PVRI0l0KrDGkMEYOHv3aCV2YR2paimf4tgP6O/2ZJnXJuaWbLseFA68n8PPpDWP/vLbcqTOEnz89mjYnYCOM35VQY",
        "2SpKTs77R+5K0A2TE5nLQgvNmQ3zKUhaNNupVXpB6EaEqgm19EO7xeYcbB0bCBWBdfB+uIaboMrCYRN+FrBiqysh6eTgNm36L56L2BFV1xTJmzYASqAfxjR7",
        "xJSsnwvnjfqheFsqKLgluaoGEeV3mfqjg6/y3z1l+843wkCdlNevV8Z0t7RkUgLK7VojzKDDV2X74oNxp92vREopBlDIbuvY0ct+itswmvmhCUc/TqS0gguC",
        "mLXvQuPAejK0r2httPbH0CFBjzKgzNI3nakeuLMTpDE3AHf/6zV55NAsCMPT3hx/bbQgiYtb9te8MyQ7xHUgHNeY+q/yuWxihOv2glZWM7ntXwY6gmBcN9kl",
        "ju+FoGsCsQKdesa0aqRW6+bTXRtwE5EJKhWZiMEQUlaCfS22E/i5Poa36q205WGvYU5ZIlWO1T6zMXeX+YI8pGC/sUQhH0mjuTVmrEYrc/hai6qkNXYdnzO6",
        "gs4Q8Kzk9hwsPfVErj6Fyf7ZTduR4f7LAW4jzJWL5T38UvuaL8Q0DC5QS/WZI4A9GRaaa/e048iOzFO+hdFOZOMEfDajNyFX/SLpth+s7hPc731sr5MXvbHs",
        "12xeggDcE6dUwgL7GFz7+MgwLBL9K4nkdF6QCOlIvrdjqKyerWc9t+wXHArYk/YKcIOfPAy6g6D2AJ1w2NgkgKWvBiTWAbKnPRnyNxCvg0KTpae0Wr3ksm0h",
        "uYFKl1jycFmVPaPtfV1vPG61VlZeAEeoNfP3bLh8D1aj90/1LmwtzZ9dDPqNuzlqDwgFrUhe1jroQdg8hy/10wbrMDvhFrEIkV6k3Ape+cs7sEYz7CtNZFwn",
        "el1A5uDXQuaCRaaT0cAUqfk7GuouOc3uk1GsBtpk+7pUrJG0M05iw7mkqAaoxCPFpNeoeI2hzn5lNjY6LtzZtUyU0NvmkovgBEhIVS9LbmsDjk2qsVWqN40C",
        "QgqTpiveCOa1nU3YPHa1U2HgoXzcs81wSfb62FgwI6Cdp0HwL0QkPhn5e14mEry0+KzED7PJvpXzGRH8jmquUcE/2JWSbRLepYHzKrULeTR1Sf27gFmMMS1G",
        "fJf0kV16X2Ik+JdStHGKj0FOoQuc22wLQjoOjPRHubwN1Y3uvI84w33D7c2xhsoTCBT2b72EsrxUW2V6LhKXOl+PPzNr1UlDTi2cEeDNdN7BEhs6l68gX5jl",
        "+EopIG5Jod9iq7O9KSBUeExzpOhF6ydbaepfC7g9/FW/k/AHKb8ztmnWy6YfQy+Fs7QLb+5p/mpdtFnnzXJltStW81vbvFH2SN0NpnXv9c+bfCEagr5QDHHG",
        "RcA0kqi5LkwvEQMo8oWDrIDtTOuvqqETsnYtkSZ84mAcoLhEpL1QuXPHDWeC0N6F/klKkzUogi5fRYp14M9jaVISn2is/pZl2VzsBwhrwT5BzrtKIiVo1z1c",
        "BUk+dFFnz0jRmhyA4Np5aLK02agOoe8CAAfjKdlAI1q1FwEO2G8oJPlTczqnxsUX7+JtRqCCMCnHGwJgdGf+2l79qyYMfGtDdp5xMKqDI6z+A8dufYdsfTZJ",
        "9VpbDxwigDgirW+5bYuSYu3UK+FLHUeced3Xq4szXJeG9zXrNz0gYfI+OMNOmxalLZkhle8/ZYHEZaeK0tWg4mF1Fr9JJIG5xfAwWMxaz3XAfIGe7PNvxxCe",
        "5sKkx2sRvGUeUIxY/F+Htdo0SjvnpiveIT00AhjfFB78xgPMdZnxakT2OvyG8VJoxniD4H4lyS07M5r3Io4GXB0RH2c+rn52Lh589fZbyTbCW+x+tsgzlWLj",
        "b6lu/nEbpEkYRgJeekxplALhRvad+MocXUNZk4t6zh72Rk3UozH+nDo/2jF7oBhKOktfCc1sdbHszx4krLX2yDcViHO2SMdf+HuXG5KeRXyas9Pzt7VY+u5e",
        "qbY5qNuveMCIUGHSi6btPTAEOKDT/EwCY6przqxtZaBhecZxw8JBQl+K0RhAXMiWxmkbSfVbxI4VfD3qLfEM8Qh6gy3sm9JJ+QcyxuFh3HmzzD37loFfXkoR",
        "7CvOkj6HQxsBzMHfVwhOHSwSfCp67C3N/LGcfCn7cxKtSiEI4Jg1qW8ZlWo+lYUd+mBUxom/vG1kGIKegeGsPZCfB2WMFbrKoKfKQwUVZdQHlrbvpo+nU0Yu",
        "oKH1CkGCaZNQBtH3cEAY/0dfHDRlNiH30V4ckIt9l7wPqoR9ZGwlU6KUX5xy5ReJoUvQ7lK1+uUVBcB676lDdyGWOllPIfEp5fT2gDhzlsnI2gE2F+Ov0/GZ",
        "KT6+vNL053hi1RR4cDZAkwpibnAQe5T7O5ZYKhjzaCwGf+hSvGa2Q6+stI2FZyGgY9gWDeBaFC/qhgnl4Uj8mcDUbsnIcsiHU8MzFA9k5ok1tvukvVJefedW",
        "ii5lecBTNlaKK7oJGIGPdNoS1jNN1baRdW2EEv+6T0IybgBNRfozfyFO0iBT+rF3VaXvm6BzY/uzCrtSxvCV5ZH82gy9F2RmRPz7ERfsGoX0+W3NuQZk55F3",
        "dwa8rkbKr3fh5dR0powR42UUB7JcjQWPfZy22ee6qgGVqGnLy/L2N97pyxqjZp3i7x4cTOCYWk9QzAA562vXjuS8Whg/PdPPQiG1MAYVyolSYCKJIpcU4xvk",
        "OVK8CrGOWF6pDa4hUQ56QcLv88nPFal08xKbaURZdUAqsQ3bGdQgU7fUyE9ZRVop5qlxP5GH1uTLotQGbu423EF1FnKwkJ17GBg5ThwrmBgBFG2J8Q1S4iPc",
        "TVVh0M9RPqinS7VqQyoXKdnnxzsKyJDLS3bAXpXE+omQzYban0YFkbTJUFK4ub+1mSaRfn3WejRDlr4MzH6r4yif/3n2fVaisXe/F8m8MDZJjX0oBwnynqkK",
        "si1ndmKSYO1CsJHDXSLh7bFKMeAAGic28/vKF1UdBomKd5aF0glt5QKTDA0kGGU2xIQJpWAEFal061g0ck/voIzcgAbPGLg6IwUIwPFupZVOGknOZoc/wize",
        "2VPvMFrAZt78/bzxWtNinu/O5RLo7VXQKli6fmcjXX6NENsHoyUtn6MQcbL8az+ifD+YWp/isbot5hbNQtijzM9bNC2Hm9pk4t+Uq3M4ey/ccxBEj6iuVaCd",
        "3MoTA8Ce9kZm6rm/3SvqMbGEG4QJAX3L9y7T34RJIoBXUH5S2Bw3qxVewTSXCgbknw40VFV84N2kHYWszrfImLXgX44Y6unn67+Q7fXZWMrcxqd7kHrozM/N",
        "AcBSqwkj2boIl0JkLXzYakwhDDCZJ3iNFOHoQR9he9C+cmG15fTnAQd7ypNUVgV3wTd/z0n0ekRcjyDGYFSVRfdKOiFNpDvRZStiJSgS29RqwA8bb8RfA6aR",
        "S5omZbzW38yVsNGPU6JoxpJHgpr61cXrdjlrXPGL6w7Aep896COtJPby+4+F4F7hyAvKx3naUMXmgu4ZDNQxcMRtf1lUx9a3q/jNAy0R9jTqvLcZvhVTMoqr",
        "GPMJQyJEVYwh9pNHX82CJWAAk6htflqmFpe6c7R2iCk4deRp7dBZDB/wUQGQelknVTCWse+tqMee3y9wAYKEDSDuRgpYHxi1bPo7ILt0RlTi6rX6EH7ZzGfX",
        "RK82E8t18bUn6vwRuQ08y+wh4lj8baXDQP0GUaATKO7F4JeC/diM27UKkGEzrL8JgxHicS3O7GFmMD0tiPFDd7zDJGuGw0dJAf1uRc68bT02HPjDs8gYCpDx",
        "XK/Er5P/fAImCGpZQPRuB+erCTT1KZSAuyqp8OJ8O9b9ebSNGdwXqmOTNmavbsnTuZre12u0VfTOfPJjBVnw0HVMrMwM86xBSX/C9pNDqST7IyLfZL6pKM7E",
        "FlKJMKqPACaYqfYx2dtEIW8N3CCreva1AIYQ2goAo//YflTmSbeDSAo2Pr+5fDT0eQtVWE3fsMoo0G/kccvYiibH3I2e5E1tROtci9e7gmCOPgS5bc5wL1OR",
        "/94ThRtrKzVCTK4NnPyLZRZppqGKzeIfvFomKYxY/aCXEldFYvVuGR5+SaYnbME5M4wOJLgDuWZNJbfIyZmhOWJfndtKGFGQfLIwtNzxKECUbogi9yy0r82g",
        "CVpu+4syh6KnjFbYIoTWDZu47RhD7aAGPdxl4VZBbCZzVrI8yRDKSCqfavYj4mDSnIF69FBQXz0vqUNNq4AvFrtVT13ZTccsnDhoukdkd3bAOPowZKbG7qMb",
        "nGzLtdHUhm5tlSyhP82KY2ayqTSkOBlOLH+tbbLQtWp6ZfV7sQxE4PCDNZAn9b5gMyehAnR3jmkDiBUrWaJyZhPc1oo1hxnpWMJP82oFIE173Lr3hsuqBydX",
        "IRY76CGoI8bCozOssVXyzI3UuWRrOCtkR+FtWOxSBuphAmOZ9Ic/hsfvd/Kq2j8URRNN75c4wy35bDV4eNDH61pSIXap/ESxFCEdlz4O/zcUESNvQc7v6koR",
        "wgshyARqjaNju0KLKoJKQRMqazxZb2gCPxFWkHbr1TAEpUfF6tYviuYjT9bFMHsUnp3njT+AIqZbDPqkMrSxeUG8CTVe1Um3BZDJd5Vmjbzf98r/Gkf7bxl7",
        "+Hr1mrv3GpapLPT2qkbrlCdZU/QMAkfX81j5LM2IvX6P7ntSArA4r7ehMJ6R5wSBMGangqNOx7O9q8amo2OCMn9IK4Z1n33EhivUN/AidN4gwlCOx4s2w636",
        "K7Whu4VHf6C8WOask4RaoGIN+/5FNvGxcnLW1GgPWAuTjmWFr+cX9LzoL+Z6o433uz6EoaXn8LVhHs3dwSojrKxATadwwq8PS+A2hH7NB8CViKoDo1GY92A+",
        "sf0kwrBiIKQaDEXQiw0Z7bka0ReQ61tcaqxwtmKGCBKSvg84j3MmjvGcIuaAmWdOM/HgPnCuZPo8QjYryvB7JsBCBdJaVaLEIniAzyf4a+R7Pqvpvg63QTcY",
        "3MKneiFnIeKhxtRZx+xWUqwWtlbrFhAa0SxRV6YUXI38VUatfpduNlVZv2SUXk2UCVRjThdiYCV/9oViUa32xp+eWTU2FlgRZrxjz58iDn6/qe73PL3+WOri",
        "/51vMo1lfrt+NceVANakisNeIO7YizT9a9VzPGQr5GhR7Mur3xvq5FxHycDqsY9fuKAqS+6vR+979lmGftYW+fxcuqIakMzM6/JmK2gm5wmYqLy9qcdwjrS4",
        "o1Ki+090cnRycHqwPzbxTH3njB2NOn8rMAmFdOk7kG1Uau/8wCkQDzrZYONOzP5h3Cbc+/yAyi1u+Mk+fDX8qGmXXDrYxdRtnzp0yUUSXltwmybkgMauxwOV",
        "+VNHPW47aUlgYDs7AnG+MsPkLlXxxKh3YYiIA5TQlC2AAJiJYxMN1yEPEDxe3oRKVflg0SQXTyO2UZWodXFDKiIRSK1Tyqi3PbGSMaewHmMPGjEZxvuY5liC",
        "Dz9ndDKrdgdkU6B8iL0efgUCo5oRVr9SlpZl4Q+zvW9Y3SFV3N5086CCH0fB4dB1tveTuvP8Kh1o0niBUy/upOTIkv8UWEdjVB4udOrEF1PJumjo8250pmfd",
        "/mk8+WL4KPs3aINuIQ569wIPoh2vdgopTKf3nD7zxOQ9QJndW9i+BY01+iETMMBj8JjjlypR3NOhHJWAiIizLwi9YijKvMiCrlEd3400L/zMIA3Ai3Ou8+0y",
        "Xiqh87Aiw61ZOTsZ6V4H9WlcVG3RmKg44/wThpgIoBndIsBWujaMUGf1vwjrGSjxv1mUbFJcqol4PrGVtJTq7P+VepjpqIEFnR15DXljGU4t+J1lbSmII2Gu",
        "pOq1fAfUG4l4BM/dIH8VOJHcDt9l+pbRRfDgzh14Zig2szTR7+ieuJUCQLR6g5bkuxWMCT1UH/CAuyOocm/COmmr5r2nEzcOm0Vun0vDII+F6J/wwheXH6WW",
        "ykdvPJ2QN86k2J11IlHeYrxrFM5yGAm0uzKQiEKRW74eI3OpZQDweBePmULcKTWH8gfuaIOfI1FmNjwWJceOrnpDTY54h3kQ2wFQKU2SzDZ80dsgT0RwpJyO",
        "5Q1vWB4cduu9hiWMOCVZy95syHUXvxMunpB9WKNag4EUNkVE0RENF61eIG8aWd6lsyWC7B/MdpuBZU5WYShWtnASqCBWzRG9qi8yZ+jUuUj8UD6MzsOPkYf4",
        "lJXkj3Lhs39Usfu/6YEfQ/CBDwtqH0p7P46uA4OV9sNphm92g/c/ncFhYVUzzD3b5U2lKag1Y5p0meNFW5kbm1uNmZWsBQgOqJ2jY0NQ9AVpc/FRmf/kci+f",
        "ORkko/2rLty+IbGRZAStZJoDGfzBGOgRMt7bUI/RA3fF/7b1lcSvWMHhkOQIzPen5e7U3/IVEkLMLj+WL7UbPmDqRj875cohMif4uS9Sq6nTW5IwQql7YuV2",
        "pCcwtJXJjyawwo/BHINH/rMHvDv7Zwvw0lnbpBlebyqCy+85hjYk1g/3a5xio0ZCtgosW2WOfyeKYaMjwpd3U4ALyTHKsf/tkIVQN0pTd3flFX8aKOkYm7e6",
        "N+GS5C1Vz14Lg1DoFJUb/InIeXuIwkumrsMCykSjko5J19QcZ2z2zWiXrEpbqGlAukPbZt5HORmRm46GNp0Bu00ezgoCJsEmeNm6Z0eo4MuSpM3gENg1kaOu",
        "cwWUc/pGcqVCHUGKUvWCZRQ1ugEvSBgikMznCpIRSIQTdhgPl3aVzmoxFsuPYskvLe23cIDMQgPWAcA1RYmoa6GiSsJyIPWniE6ERUAPEUDzGsDjY9bIB15L",
        "y1UXCCQNCPfA5BP1ji5V3/e2ZLyzhQ1271MMY557in5nVrxU9lyuD40yd8TboUK3ITq/GFzz+AOQi8JRMRpsnbdTWBMi6MIH+U0m2fFiKonVukTy2mV0zBdc",
        "q7gpHxC09E3cobMT13TJS9hcA/vMCKl41nGEehHgAJavwOUz5FU1LB0WorJDL9plQSnYVoOMG1BIlKr3XKKP0vgnI6nKMGlOoUXOPBaYA5XVVq/m1fXRbewX",
        "N4D2b9h95Cv5EakboNhz5SvREicN7Rs8u3CDU9A80jwx/FR4Jp+iw3tAUhKg/PXXot55Qkrh9Uh6xwFi1hgqFObyvQqWSrZVVZE1SmeRGHmt8PRlnrf+d1md",
        "WpLfjdcJSnME+Bb+9hbsLj7QMWGm0hE9KxW8degY/i/D6PNfIAWC9WgKuck8ONvBUMcAXK8Dt/9EliOl5wadD4JenvfVTOfje4sDek1zl38jAa+qkM7AXTfL",
        "MRSPv1qXiznQuys+CYi2gOkB8WwQI/HFTZK+tJYT+qydfke+eXS1tSEDUImifsEQMJxGBDwBWFobwUdw4wV3ACphL+tDjmnEwEqUFwhWBek69zlAaDxh6qrF",
        "ps8bpqV+wb+vGheoJnErYxDx1O8FDMVytUU858/FBuJqiUv0hxQ0tU9YsW3jYEoy2FR3EJVFhUp+RYBNnGKZGB6yUt6TeYyHKVIe+tFun/OweGCAUqpl/rtl",
        "p45eK3uWneOVEM/tfTYnj5CWIobqQzqrzRHCvYEWfI+DPIxdE7OqAusZMoa/9B+bOWsqCMjQgbko11hd7W+Yr+A+CrugVfc5W6cY1nbYr9jbJgjJ+l3OYewQ",
        "xiJAL3aqG3nrxJXVgLqghVeyYE7XP9sKJi5Q12WPq1Sq9junAzzx+uHFVsseneudJAmBk9YBjhrYZoTR2fqej+QarbRPfVnaMBqSw9Zy+bMhlYNo9m0qjgme",
        "odeVT248PDyaiPXYGG6bmBV/BMyl55uoiygVx+gVNLElIWOYExeobv4k4OK+1EztmNBH5wQ1wlpw8FCDoKLyLLDjuqiKubtJw94UJ7nJklAucTGcIoAT46CG",
        "owvYdSYQf8RqiglitpeO5Or0MK2qHzIqN32m/ySLi6mk9bvWvCLPootpTqBOhZN0ygRWRB6/6WGGqtF5tCTJwyuITIh7icBd3k/dHY7qfQe2N5igNgHdpbrQ",
        "jKbJXUJ0H8/myeXo/ntSm3g+7PUomefeO6j+bVcUu0YW3kDExAxQwf0TFQDkEwfk0MTn9KvHWz+ZIzFxQarCsSRpNuPd+ECDWK4SzpsUDufM1dt86APAZHTj",
        "tu1L1A9pcO3xkp7AJrckmhwgdCs9E3VUPrOuMQLlJqjs1RzB48VUV7sLnZ44RdV54n6XilYc15Dl8i/iXYLnR2Oun5cbDF4pDWaS7UEJqYpZgPlYJJ8hUC4T",
        "GvJm/dXntCNWMyahfr6dWQlc1BOnQE+GG1ToJ4mbEeh0HqVlZjWhJG37qfMgLugftU+nxMG6Qxgl9wSZmurf899B7Ko0sM3+XPR+O+as/Ek8BUIbgGj6dtGg",
        "gLrwFPHRUDjDgv+m1Mr4YEUMd6QadGPsqFLDQTXm1oonaroSsh/t4j64qNlTnstUHXHcWmtdrx3kftz5eeb5kramJGrvw/wIGnVRlCs4WZ0yMQI3uGi/nR13",
        "NmCYDGvtoudAEvQDWVWw2j1Jbr4cKuLw+gWfl8D010AiWRCiNEDJTCJiIx6Om7zEMSRp5cp8mVXxdD3e8Sqi0q9FXEZOrgBDp/ujNirfaJYm3bC4apDXLMdo",
        "xgpOnM8pcsX7fTe+3dGapLTcsyO1Lk2+uzm4fhBvUjtzT/iJMh4ZXGOKuYtFtinSbIUbzOoEW+XG1M5lM2WjEx7iQfKfw+scUGWGBoZ2cA/R4Dv2SRnPtiy8",
        "4JY/xXTPvHrCVauIxRtOh8gqt4ES9ROo9JpAJWzTE5CZp/o4IAZq932aR18F3DOIKR8hHvLbOUseTsczsRzFr255uzvXeEOckImwH60eM2sPu8lBCYqjk3rt",
        "z1spI/K75kW9YbsC4YffpJh3LO2azlPPAGSoYXF0bV8R7MLAHeKuza5AIQ5wo18lImf8oVSAfRTgpq6TQHoa9S/WBG9kQMa1V/UjZK+EwrxAnJ3jU22RW4YI",
        "zesYqIBLaOkk5C9z3Q58oXlZ/HuzpLcEbJNkZPw4Ko5V6MEfnW6bHRVRaHC49rhHnIhI2CiXmfsEoQgpArlZTu94VjnpvA09BHIx4mYTi9T4cQHPPE1giLTg",
        "rRjxBCdJ9HGzq4pOOBMnS60WtAYDppmg7leWTP/k37G8BfvAm4X+cszQE/7PKCjxGVswr5hcsOuqCbRCapTGozetseCdAZ5kDSMpGwJaar45rXDRIF6S9naG",
        "SfuNrZjbnFJl7btVphZE8C+fCgqJgMxjlh17L46cNDIukKwpd9ih6Wql4i3YItLhmnr+BLjmDHEhAanZ0Q6MkUXeiPqv8DNPD0MpN8l/SjJeY0C7n5pje/wl",
        "gtkiWPD5OFcCnzuZJH4eaTQhsw+SR9t7H4jm0wXOGZ8oNMNW0ynEs9P0BljRPyl4TceFJAPwY4D1+WKlBKHYDDlMGfE9qsMcGq+haAOWhUZt0AI3WzGId9um",
        "DJFsyCM2Q1+iOF2aV2UcbCYXwxiIAHevkWHFe2HSkqPL+SSv0c7Q1xD3EWAV8+DwglyujRIblmQy85z0yw+vu/IkjoMxmHFn32ccYq1cjFrzPI0Y/XoXs1rX",
        "wnLOfHO0ZH0YmZVO1N//IbyK9sIwluNza5Vv9q81q4/mQ6Ik1MdVab7RADe4yj7j7MADDOe9MNCOzHCcUKFGv0AdEreEKLO6uwYs06v7IoALIHWk5qoVCfad",
        "kZ4RmCqOjTzgtxhcIFApEA4yTZ94zR8LJcovRK9Y/JnLkRbN38974vpumS/l0KiIKcNzmJKSFFN9jLS91JtkPQfpskq3BciHoMsqHqajvgRUI7ZXZhN4/Iip",
        "65/VkAAQjIGJf/hISblFSc9Kfz7uMI0hATqBSj4jDeC8sWPsrw6mq+MQratSLWwHFGFbdaWsvRy7kADhpf8XhuWS1pYD7KBuzC+yFgXJALloEuIbSqkfKOVH",
        "NsplknxRbDOb7iOiGVOxY9wt41lfHYmJ8wa1SaohiEY+fhw7OswYpafNP1U8/SSJhXeRIwgLScT5M5CNKD7KGUGxXvw+OCroDc1ZG2jFExNRp0iSPLRnn3vS",
        "K2x9/Uk5LcRlWQJ+rds7bsEICMO0tz9gXhQ5Cyg/ywPalchkH90zx4DazD2iWgAdd8hwF35vXnT5plmVWtk0nO5AycKaRVBDuq5Sll23yJ6SF/m12T8O/LcB",
        "WkSFunMVsg1gyjI55gKG5nVUHaKUwxrIMgrBbPZ0POJGcxrVpOcrJePY3PzLxSCSD0D8AXYdtc38vxiJXv0AuJZC+ljywteQDMRk1NlhqJe8FR0f9qXnMJaa",
        "6XWRqwbmyooL4mYnWSfjCdkg+QL96fh/yj2F5JxC8fwjLVHuzfCv9+sBxc75i4yJ9oYQjmTsTut/zbWOuv4h3kjOXR+41kltGAqXwqLTa5hZA6RSM5oUF7R0",
        "fml9o5EfsIhxFeL3t2vfl6rBwkozc5E/NFK3/KS0OpROBadd61YHEPhYiCh26NoxhvHV1qilcAVqLK4KoJOeb0+vwZgRobsJlEbPjImfkot3mFwjCDoDGAou",
        "gZaiZvfq1RX7l7MFIu/FOvjuUjiOUIW/RdBil8BzdJ8MRCCL2jJP8xy0QPUCMlhdzjTns4O4UnqzPC4ghVT/t6/XmFTy0PyPXzjai5FwslVtuiEzJclRNymR",
        "0eRZWagBmj01JYiae4/YN6b0rYAgl2DpapIuOcVF6NRM/9Gs3fS3MW4eIsGJNePD5Hpi/9b+kn+3vr6WTX25HXafNfg7GlU7CN3otu7kOncg49M241naFlkL",
        "ruG7dtYSYP3UF5nJtb8/U+icK7SwpRjF19OtRZgkUrCGnIBFhoCuNC3pE2VNdC1SVvVWyol44kOuISoE5nITVGOoNXWhdU25/uJzimcmNqWEpZVxySmhn9T/",
        "4kGt6NH6cY2nFngZClSUoucHi6gJBDdMYXoaSV92wFcXPPDIiy1PJsSUu0FW8klET9hTxHCqo1gDAs/hsTc+sHR7RQ0Zm+OrD6ELBdArPBiRvRcJ296uXO2s",
        "SQYHn3DFuCD3yjUszVN75fANLO3iwLdCjzk7zJZXWH1jWzeaLfdNJpuYOLz+nC8qKepqevzakmWjJcHx1nN0OqaHAzxdx1nbCk27zhL1DpTskgDEEdwOxFm9",
        "fpwzELnr62ZRNxVz3O2vFgm/qi0XjfG/LwgVq/o5SAjcHgrFEUIkuMRnkLgpQ+Jgne0lWG0co1OJOXeEmRhpC+OanoT6zXUIBgihZ8EdOXQYBRndbjZqSn7V",
        "rg84jnVyxXxpr4B+L0qf1baBh6vNNr3HEkKeCldxNWBNLx2mt+7KNPaSVhSt7lIS7Bl1iMVadVJG5hz3F/pB1YZuGznH1A/y9D5JTKuMxeYD8FHnzs1D5jeZ",
        "L20nTUMy1VXqBR9RQXmIibEz8yVatszACwsa1jehE1co4GUV1EdtSTAK0EjZ6hPprizlV9JdF34YhYL7+s9MQDiDGYWl9l24FVv2PJNT/vFEdEGBT39XLnnw",
        "tvkJRXzie72M0gTlsZ4cgLz387SkBL28cKXW51ElLZLTCKg/wIE0B/vvHp7KsvnTd7HWfK/h3DybjGttDb342ujqQgzjSOY4Zx/Gc21U0+gGYDf7OTZQDtlg",
        "bn7BLGOI18Q9yHF9Sl1vZEUAICdS2rkIKCXvUwIwUSBKViBhT1GlDNssqj6TSzq/tK2heoHGBNL/7NiB6MRCLJ9U9uclD+OrpG0d0P/ZtQ/eAygH0VMCJKtO",
        "yfV6zHbQvOOuzOHQOlLhw07V+ZgFTcYMSZNjPTPQ/RKFMcejK2yRgZ0m2KGLqbaZhNNcxr8WntGoxpUuAqLDBMH6aOYE+6F5wTAYy4p3dFFhg7uHgjHq/fnt",
        "56eO4xqM4dGF9ktR7FVb9TbZZwZmSFdmuiVw7v4wv13vWJyTWeoQNSoTEJfmJQHI+TVqvvLx41jSTFQEJZhug4T1+hktFHB3eHz1unvfFX3ZIKuolYGcDHMo",
        "pwQyoGplle2PVlLhDylmtsswa6W1hpHFEdSywPDbo0VV4RBIQbn4ZMecVyKlTSb9UDS1gD8TTidPL+MaaeLL6YFaQKJw22Pv6FTNvwVeyJOOv1YZjChr1VnU",
        "OVkiJ9UEGTfELjXgsVZUApJYXS7kO3c/xN/upkvcwH5yXWNFkcetypvz3nMnj1gpC+LsKUs8PA1TRF10QUiKBmfzgUx6tsdRUgXVyin2usz9el88xpyuZTCB",
        "YEKlRWoG07qSE83OC/bkns6ZY3QiN8DU4tSezwq3xL8xTnwmC8uLKqxfcyrhJODTcLttAgmZiBEybrIksVQ7pVmLreDpGbej1TRZBoLuxWBh0Gl7GTkJ2yBm",
        "YZYnft6U/XOmjSSo7KNLVyC3l73hYh9n6m+uEjtQPiUSGTzZsMtt31YN0N7dD/lwmPZ9aNnD/p5Z4PQDeryZ61f31NEni+brqU4rCtVz6IJy5Esi7oqoETtK",
        "JKsi/cFmiJC9K45eQC0G2Dp5FLVj3FF/QOauLNsIfO591aTmp/siLYiJtL0VsqrJi8cfRi6+CV8AZAOHG89wOJU+PUaAaY9J2kXbtCTnpyzHYx+tGFMUnkCU",
        "RZSQhJnn/g0NTOk8Oh/FRHLd67hFlyrNvkkgCnTuD5EBNhYT76CXvQ0R611a4DLU+iypa3Z9N42d8je/v2EVVlRWso71DEk2EUJPdQfYbU/z3LlFUHcoEw9r",
        "gQOFwkIIRB4+I/wR7Oix+XafUiOnhHlCOVN9s6Clgl2k/P4/XW2r3y0h0FM+rF7+tEIT3KzGttlWgA2x50B2MEdjD7N6KuVtKokMYLN+/dwQWtxn8hTriVe/",
        "MnrTy9K149vcnf0/FwKxd2iDspTfjAEpWdEzqqey/KSr7U8XHeReGxX7iDwOWRnRbdaRkk838+ryNyxv+VqnX5Cv5fQGUtPZ5RazYyarfFrKKqLCufkmbqGq",
        "bhGqbyYIM4Ddtier9c7/XeASf7QmuFR/FFtJg5/1mxvkNTAcUgj1YmOHs7MObkeKbmP+HnEHWziuyWkkCsj0IoceF+FBzNn+0fAhLXlvcyjJXCv5XxlPcpOM",
        "H7g8hkJ61DAup+EjVqqj6011hGz1u/f3JnzOwyMY6uLFKLRTlky3hfbPXRSbZvmxk/8XFf6JLqXSC7ajsPnXo71nHy5LTGzX3CNslnYhvTFwyEWX256asDvQ",
        "4Uy90/czIzaSXTA4snG/mamxhsbp6yQJM7zNYCXjAsMZZsXS0d/nMJaTvh7v/KxCTG/HD4T/mXkQpx4kxyvCo818dUK+pqyEmuVpdlJnGH0kikC2JnLvgp8T",
        "EB1aXyhe5Nkf45JCoe3RJMflfrBhSxUH6wRAWYlgzNEFa8MfCGf/47Q2WgeNzWa7GcACXBRuff30Yh0yHT2EpzOWf/wJz7okpxVBODhUYq82dnhYQDwKjg/J",
        "d+nPjDv5xSLIvjgicSoiRdZjpMk691dFVFrWBjDki3k2mZLz2UJR4YgQwdA50ncK5+NvKNduhXSlHX0vRMapzVOQrdYsN13xzKEYDBxudBYS136sCNcM+y4I",
        "0yWJY4TmbTSZBqmF87R849QjFkx1Uf89u6TVa/Q/U23BPJw3mQjJpLPr0tr3qjnRAeMzPk1UCpR1bJmeFcpP1veCO6MBAGUtBkyqQZ6hUvTVKVvK7Ciwwy1G",
        "ZqUIBkwEyNoCVur48RrLHzs69zq7w2KcD+Euespl3PClqDRI2m3BTBasILSNrTreD6oUrJG/GH5+t2wBFsZVNJf+OgM+fn0h6t39WDRB0ebPshIpgze0XHR3",
        "OTC4+6WD4MoO6/tvolad5JQQ+fEk7/uwdu4WFz2CfEnx77chkTvFTmjBFzXTlaVbrUpcEteQFPPCLTHHhMMZjYoqIYKc5NGfr/iPuxZJmFL0MUXWNpxU9zxO",
        "jTgXXBlhfo/tyMDtENpzBGOyD/ysElHH/8V4d+8yRNdMGXs8pvd31R7yo0FP9gRY2XWYFrMBtElRLjRysElbWh1Fxc+PBLE/HlKaP3hARna9KCRUD8gsZTv3",
        "eLjibz54j2ZKEoTjvQR8jxDR2vGK5SZgJ/HzwEnhgTvkDIrBZeeAhHad4HvbxJ7W9T4XuISn9d8W+Kez4BfJMTNW7sULuOIp5ijpoITHBM76Zhs0Dy6CuzBW",
        "PnMZG0SzkdEKWfHOANpqAtjLcrgMJsLzw8e35BG6EOg7LeEji5FpumX3Rnh3DeaqY7Pt0h8LTN0+77MWHZ1454C+iRF5lHTt/f+StnF3t2eg8aHpEF4zYNhU",
        "o+fEWwRPes6n8YglBAVFBJJGSDjn7cWtjffL6xjmbnQfA3iGhSVKsgDL6lpBTGL5V0fiaaf8xx9/6jqFCqocMiUPVdKuFIOg+FZEHOF+Vkpz86MQyuoWhkF0",
        "h700aig3epVChEJ8wku18rEcH8CrQl75QCrHYMRRso1tEpbLQt2+JVd11GU9vKILzvAkrI0ateSRzepf7PXiq87nj4jxezrb2hF4AsdWCllV0QhKUQBJNUdY",
        "Qa/ZNGKzgAZ95DP80DZ+YclaQmVNPMWUrFtYHqClAmbHzxmH1tVe602jBqDdBOeYDd9oqB6mXMQbU5oztXAyqNYUwfMlUyFMhqCB9zgzFX2FtwCHzitRK3zJ",
        "/vJFazcM5KVZKeFYgWXYBOf9I3Nt51IWFaALbNChRsjuPETNpXnalBX/iP5jHBftBMwHLj3jsc7BzaiTZQgWIBvzv/kwbpOHqU3FfJLNvH0tuSqqgainfXOH",
        "z5SgMZpAGGeCAYV/cQXOBwYcUT2SxpG8UkbU/LtCm2Tv3/BFC93k8KY0EC7bTzyaf4GMGpN3IBvujhrWweec0eD8wFOoVHqR4s/yY3pmPwheD9dkzwIgZ2jJ",
        "+z/vfJUIK7A/WfhHjSaEiLKjPcEbTUwynIU5hMYb8cX1tk5cLBF74i2TFXVAiVu5cJGoJL1wVL5mMBK6mYSY1hzaatbSsrfICKg1yLIIBk1FD5XsuN5C6KtX",
        "3FVss7RY4J+i97rWfAG3ecgZZJRetSKpgCFFJixgLng/aH0TahOlvBot3Gifuo1wTk//ZVhGkrqcrkKnYkoghvjmSi9sBs3bD5rZyiWmPzBDAYW5OuCti4jg",
        "xcj7kJAlCWZ17WaCbUqj2WJwRzYy4mn54l5U6NzUzNtt/RPxTcpz4cmimPIw0mUCR3NzYeUR3vmILVz4wYhjsQ4jpkdbQu0mfg+j4Y3SgJ0nwIJfpEBuNwNP",
        "Unm3Lw+XLheTE71GjYYLgixte8/jmgtBb3cIbW0jrKVAYJiXPaGWffhCJGhLD41ARZtvArsxwVrjdjying7Ng7k7XNb363pTnw14H0n4Vvq1iE6F3O7YruGF",
        "1HlUyFI+VqVVIyYANW4f/9YnQHNbK0xWs1xcDG0vazlxYV/Tr42F7JTY9LvV9HbgklhSABMIZJ2SodPlgYTyO1xjaDZYPRCc1FSwYZjhhQHuqCmMUe9CkSl/",
        "oKPC7VY+fXJPg14BLtnbtCYRlc34OSdsrkf90sYH2QraCBUd7K4SOj986AtXtXfRgSEqhPqDHfJw7d/OMEGkPdDpw2OrHwtFeK8tBY+L0PT88K7U0eMzR4h9",
        "67SBSo2V5I7lMr9vwztVhaJh8KNUEfBQW82HPihtwQTeqw7SOu/5YZ6xzxvFMZ/v0pFGVItJ63TlI2InQjkN60lLdIVKq8RGg0r1PcTt680WbTk3PbRbcNDZ",
        "m7PILrCP5OxtWSMMTZxzeUXH+CjhSoP954pHd64K5mK8F/DUMz0HcIq7vbyD6bRJGEn9ukFiib/L2XOLjibUbfVgrGPEQXhJ7uI6Qq3rqsL70z46iokt4sdH",
        "D3Zhf5itIric7hlxIz6xA/Wo+ZG3XBO6hMKmA+E8sAvTR1ZdaXfNVM0M/22YPkJgTFlrApuY4eQXFiGvHjg2x1WU5g9Io/+H0yYlHJdE0NugfCME3PDqLj9x",
        "hkVige/20FmX6Ldmg68hKqvbouNVO1TH2iDVosFfZ4AAf/dwGY/i/O5i6n1NrDZsjwr9Q+YAQfZdHTm4XRWjkICNjpIKuMHtvS4RK15h/nXYOMoU33WE73QL",
        "XpdFaq2hJ6oWIaQQH/qlkE/38TXF0gZC5wD6DX17HyuxXw6cKKgV5ER9SgUicvACLXAdC+N/v8oWY67N6WNyD/5ROgQxQN0CAyv5EXg28Pq/OuKT2JrZ+jx5",
        "mQv/ME5J8RJV4fzhTTGd3okEWQHetXYaeRSVJe9/9DhwTkajI7PQaZ3ZHJeCGvd9PQUc2q2Mu++INanEpwMBa+Ea/E3FlB2OFB9SrhsaUOnNvziR8z+Y5Fxk",
        "8j8x+cG2IZhG4zw7UXLVuK73XAkf30Jg6RueRBNk369Pz8RkmQuoY/VeLsEuZI/UpkpJP4j7gYLZvWjks3dg2Q+O3BGds9yA3HmIdCNKw1rBfgvNxqMRTz+l",
        "atDpX62Lkc/Ej7B5eB6zBTlZHq1YXyZVr3a8wmNfbubbgIhYl8JAbAAzw9Pnc+ekpydp7TtH9rKxfeHYG1+Gj+x7oJRniMJSCQdtGjr1wxaRkCr9sAHSLXF5",
        "4O0kV51cBr6rkYNhc2UkZjtG7DPwXYnBMpCsPnRXencIKq+59yNDx9fLaj9ocyjNYbPRIOcOZD0SWnlKWKAp6rTbUm3blLsFqf01gL2PR/e5i2Bf4fK26xCI",
        "+xXJ7ql/cX+wq4HKOsNs1+H7wk0fbS44mkSGJ1aNexeY5lZPTrIu2WJEp6orVXESfy2vgMk0ck2gQa0b0pKg7GnxQ25GxHCdsRH85rO6cOfI9+yHLIeY0Jj6",
        "5SPpzH8rmO4JfLaH2gTVju1/NoCxRE7guG4RrOnljfLroYvgxxgngcRgqNlMSDNm0hZ9SYbFS0OZd153BFH+M24NmMOQMzqAC3B5BVPKKLoEKN57d/w0pot1",
        "/gvN1KYXiVOr0nsbDjuWZdyHxrd0qBnPMpxYGu44bkryhPdzFYh5n61iugVEc1H4xJYGDEwFwX5Zl9djsjuiXXsSWOQkVACyxDUCJI3iQzI3ySo+EinwU+vj",
        "ZrebRvDTqY3uSQu3fkj54jvrDmrIT7EliTtAVtbteu9T9s7aGr1TgqGhUTWuvXeKfw/ovXnN9Me7ptfHQcIu7/K1cM7sC9m0Kkul4vYEDXAhrxjS8sLWmi9I",
        "tr9vuuOY2us2EZ2NyfWXyNH8GGIwiOhG0X6d6s0+Mk7lc81cymZgK5KxPZEmcuRqqbNGWCaSY5tH4Rg51rnKfkUoJ1/TOqcr7oTtqcK/xpY2MTjZsv2weFCc",
        "fgznTikVh3iGj1p0aG4+DG6yqGHbsWnb4zgZwUEHuUW55XqWROFeczlk2N5WlgN5xTHdNlMtEeIKoY8gGQ33QEHgmmPP5Jam77N3I2ENUBfxIszaOHyzdzbD",
        "qdAqNchRSwT8CM950ZpKiuYKDUozVLajp6/LPVMPBYgCdHVtzJCuyupeUnEOOWeNvJ9akuDHxEgi+pTeMUfCVb61cOD2pY0P0U/vp7m34UDmOpY1oR/KYJVd",
        "yQ+fcW32whAa757GNvyAXRHF9jqYINisQum6DTdunSu6vEvjlGXb+dznIe7D5qopoK2O+LWKuH4mAXzVjlyTXM5ac1N0kmB9pLuZPlTccg45P/9hGM1nYKC4",
        "qnqYQFvNWSUDszdYBYxhNUgaCeV7VqUuXwGI8lTDJCNyHeJBOOCyQ8jrCoYwyj2/dgrLovlRduQw4ZTHIlSuptYR9X2A5poBHfaC1U5kZgArIT1Y4sssaYUk",
        "po5MlfTYjYiZZYDrz3EeyY/s/SynoGIArZ1483SRNs090FCdi9jYzDM2ebRCUj6gd8VYn0l5AYka0Ixysn28aroVsY5HTvidKJGdaGyuCoLoprUMMN/39dGN",
        "PuhRt+XB1Rp6NQ5+3j1633f4/OdkAri/n1xlgZCOdj+WBgpPN10uVlvxNJYnvQAQzepXr9bfT7OHqPdZgXx+vIpRh4+8Wd5Qgd2nGmeYM0XNGY/9pBiY+ATL",
        "ckNmWUTHwqBIbyjU2qvEsuhTawCPt0ucFYTo1J+n++HCiO1ybj19QjfJOBYMf924ImA70Qc2Js1ABsMDOU34s3qLMjW0m0jISU6TiEUp/4v7Ycfr5XNimZ99",
        "2VAckTszgOYjhkkF8QB65mucBO7ikzo25utEIHyaWBYLuljqwN2QVwHrAvibW4iryXirdMQg19H+AJWGE7k8r42Ch3xyd2MnZWnGh/mzog4+AttIdETZsvsj",
        "b5S2ngcN6WlzeYuGsAyEeXGYxSUl/fomkFhXdSDbWfAjWMoPDV+nhBr5lUA5R46+XJXSnEWUuS8guGJEtBVerAJJXfTHbL2WQvKFv7VZWP/NGMZ2E1f0I57y",
        "J6BxB5bh6TvNBkDtiNXIvDplrDPnd5KZf9qRieSAdxuHKJ3m7/7LHFwK9L3DxJf3jQ+GvZYggjOG6g3PEKDDJffLwMrCmrJI14V5WcaglN2C1GrtPhwZAqzs",
        "RtPwAeAQ3XpZ7tPzcNtorO6JwUUSX9izY5ri2TPwEnzdHncNZcnz1nHuaMCO8FdRwHsyxM0upoKOyIMkgNu7jtZung9d+2+7od3l2zipjjPljQeH+os5IswE",
        "fetIqjVoGgzUeTl1a18RQ+XbArE0OXHpC583uwZmH4/0C/fLsWcNB2SFqDfW4SWHu/4wqUtZAILdC+m/m8FBAjMjSpTosCeeCzbpcBZeLGlDOl7lnxc9zLzM",
        "ZwMIwpJLIFLyD8HMEHyttEMuYXFqvjISIw/QqBHORXpkX0uORJDPxa5E0PVEwGlkZNCxSYpLhUY8D0ZkVVntgPec8f7vZi7tdHxQdTXlKAAwtQQWOkeXnYIj",
        "THZyom/AJfonzlFylwtTYK2sxlGniNWsiZvCvb0BnhJ/6IFrAK4yyLcxCcNFtpPrPjpOriwI19ZHq2/pt+WaK5YkfWoDFpFYujKVpQnyE0Q8OK5e8dgCIoCE",
        "pr3bh9QjqdAB/rfE+NlO4Jdn8PS6zQr51+tMuPzZiaq9mu6pXiHQvD8/rH3rwA1Met9OILUxZQ0ml+t6BlEomXJ/mpMLZJQNfls+keFz6BLyIkKaFGsynte+",
        "BXRk6I9CR+l1Ie1YMbF9O2O0adAD3Vp/nAA6dsQxStYg2I7alU5aOr2yjVo/BJ52fqqdN4OBptbgJ+OEVskJN+9prgnZCdET/FGkIdEPM0eaEc92OhrdcNwk",
        "s+ZKbIRBDXQsO34MjpCUIiisMAX99itjAmEcnRsYWF8G0ycfxiJP7uLf3aFzR3wqmOm1wPFdlak7v9TEDLuHxoqhg05Bixhx+arIehs4SOM2anU9d/3Sc80/",
        "5z9rN+cHNwAHRYlSjPwgz9g+Fx6hQWfm6JVvQO9L1zjQkdSt6DfZeBeBqoVAV0TElIV+0pmDhRspxKjId6VPt/AkixCs1NfgBKReC675CtPWR/nETlotpgRU",
        "H5ROSTHKx9wGBoJ978YpFNzMuuZzT19+tzCsYipwuLb6oyR2rZ469wvbkIQjTrEeDT/wQIsmGlefKpQjhhU+QHnZMeDqV/aMCVPqoz72uJ2BfBwNlmnvkUe5",
        "aH/BlBlkn34Hicv5onxAfq8xhfOH34xuPHlec2lVKShRM1ua81QNvm57Aq0SgVbSwTJNrD5Xysrv67PLGX+RbDBRLc/p7oXsfo/yoz0rlpt/QQAVF53W/elt",
        "lD+qPuq4G9zVjagWzIfSCQf8uCmzijvxO+PFiSv5ypwjkkCpie2y32/qcOI5VgOoR+Q2KP8twIv1gi/leQ/8R3SQnS9D1z6FLz/ew2EMCYWl938SdYwOYyC8",
        "6AhFMtwiqEPNDKuNSpfildqKNNFBERA1euY9QQyEpHwJHOP1vmLq3IutNePeaV7doBkwm8eI8uLycyavsNZDxgwRoXTNueupagXSu/QDUkSEEHLC+XUdX2LE",
        "9ztEc0ljBifoTFkp4i1961l90r4ZIJjXo/2JjE6CcfafM0cU/6rIQajtfOLwTcwI8a3UkK8GwVIw976/3PdLbtVB3ktlbKnuxd41RfsLC407xu3lkm4U9zoN",
        "IDv2wTzi6Fbx9v/kmtoJGwFPwiP825PNCURPSuY/HEMcbdRH9H9Kvdo3nA3R9b4U0qrZiQDOQIKulC/NZBk96n1wmoib7+67MDkCI5migcjkjG+EIQfFzkGm",
        "PcVgYcTflO5IDAY+RlWK7DXh533XWlHIHDCWhBR2I1u/9pv3bGz2v5qqGJgE+bsT0Vvubg4wn7pQRRsv9ayEki8HZrDPZK8fPba+vyxlycIe2dXEwTiNTuY+",
        "zMpCqGUTFUA7P4e/scs9Kccoi+NStOeVOamLfKwp12QCrGDti/DCGqMsJql2oP0eVtTSZu6hZq0r6orxYVF6hZESLIq0muyoC8QjXFoptv2Vmaxtoa2tBDCN",
        "Zn1wxrR3C9ef+Pg4ah+7FLHZBiKDQ5OOdTt3aVAndQly7FWF70Odq7ONFsKEUET9DfqH0FOYrN7MOUIzBM/7jS/YL1RXGb68zViCQR/VfJprVYf9YLaV/v45",
        "/rg0umVwVMZzoNrGWu6AsAX0nrKEOgyLC/EJ5wMtuPM8U6Sr7CkphvsKMBTiCFVkji5SBwZdwtCWiAFU1tvlVpAwAeu3aJUbKzJO370t0u+PoBkD/G/bZV8u",
        "K0a0SM0fPyKr/TRBzA9PDPySHoBme515NvIbHUHtbP4kr4QSZY1SS2OlFSTNeuakwKvqYcgrmMgEQK+oeE27ZIinVEJJk2YCQebrUMD3fBXn0TPIe/RbFbwV",
        "8HrhdZMopz4aQt2nhLONqGZwkff3ONOYvaNG3Sm0H3jCqhDI44Otlvv/7LtE5cvjEMR10eSOX05d78VFJ24u2NdvAFrGFMrw/i9JsyxZCSc0ylg4HjcUFhem",
        "mwDjkbzmUVqZSvCiIDdwterQ0+KUUnGda8/f6iWrvNY8p8cgSGnY86q7E5muOuECFvbMbb1z4o3Mkrx98lxIuu+EaDO7DTe9m0JTMqPopCo382suI7Y8othj",
        "lGUaY/k+j0Rv3tDX7UqpVG7jlApvcEbko3dnDgTdMVWZ4jfbug8XgwQMCxY/439rwWUpXIgzGrncAGJHB3okNPJqGf7mc4DQDSZBMIdlzuIQ6ZpVJvgxlzgr",
        "2kgjUR3eugEc43X6FllhuDHaYRc1l3A8WSIe8AxVoC+IFSA+jkAg9fDtPI6zhYSRsHFMayswhqoE3qB4qWxPvuZyhoxSGmu/bb0vEfkygHu4D5tknnBSXc1O",
        "lDz84/ypk/ToL4fePjMVS44FXlHz0clAzPEoWgtDunjzTEfqLHkzeADbEjhRcs+b4m+Q8u9SSTZE2m7AWBqRwtUMjWhUedzlOxnHgimcGj/6nzkV7Z1rRd/S",
        "68gDlKIKACt9q0POdaK+9gC5YJcZlHugg7GqNwBz40LfcfpjdJWaNBV1pA1V7a73oJA0UylFTosrOBWSl3wrnmIG0S32oeBmjx+ROfWFkZdrm8WCVoD6mK9d",
        "EaDNVREvsNbdNZihCneHoQemU5ZXQ8vC7r3gFOQD7TKPYeEU1YDXHzj6mE+L26vJgmu77HUo6txmNpRXGWn1FeC7Hziaa+USTS18RC8fA4JbT1WgCxlM+O9d",
        "tOrJA+oxy0kbBEP1La4hFZrOIPidhbn1NxibTgvMJG2SF+Uq+FuS2elZTzQBODlwVfuwHXLbS3vcdNPQhGR0H7SkvmdkF+wePR42Q0LwIKP/rAGnfEd/9JGx",
        "nHFPTQ/yEzTno7Z8CtsFlwXTKYBL2gtWSkXJTVkNjK/aXNUQe9kSp7yQ8j7SF3FxXBwM68FfGvKx/xKaZq/Ghv3NKmrvqGy2tkkKShan0JtdhQFyh1Gz5+Jv",
        "lJ9/ulIoQ50CJvKerSAJ0LKEShJVUe2wfBJnpJ1PmgiUk+HmD5yUAw3/RJWU2tWhJv+oj5mzttoxhaxPZ5LHUA6dwfik1kGeeCi5KVWcXO4KOWsenHcd9Llz",
        "nJMSaJtpKd1VE0Tf2d9F53RblRQ8r+e6LSj2QqL9u1PjiHu7ggO+98KSeECtFeZSDFdSiMHbwK32KbNvfSGRC7SKH/YcF+KxpEMenMCy2S7UEFvdkXQnpYMo",
        "u6Eq0OINSeoFX+15zI1kRDyelX8g5JOH26fI0nsya54vse2+VbMjnZLQuzLLBgY/7MZpGNqHBttkoFypyGatAd/ypG28X7k5O8Gnd9ZLDKX37WrKjAhb9we6",
        "Xbt4+EaYfddIUY6uHs1nzT3MNQpM3oIsF70S3/dLwBA0tfmk0w78HwL9UtZfOBgqifU2w3y6YkikqGG2Q/YTS7q97hxZQAd1eW4/UCfIa0Bjb7yCCwh9uKEG",
        "b4FY9+gFW00rxcPU79pmOHY5XnFdly8dNUu20/r4aLRKMoBnmHkyAULHDHndWMEKqD4NIf5Z+xEZJR3vfagh2SrcawI2T3amxpDlF0W2BadsoAJsNJngy6B4",
        "EKVaigdUKL53ed7aztpFVNidbOu85Ry8BK8MTiHfVpd9VRsbMQbFg2gilMMSRMmfNrwakb+sF2oRSXe2AwIY+u3gvpLuINXkULCAARNflkpn7tU5pQU0O+4y",
        "vi9Vh6shCefrsyljzmdD89urz5CSxfsm+j2HsOpp0v7XWWeUP/IWRVTOqSnG1aDXn0gXKdydd7gIkwvqpvY6wFytXiWOvYrfjgphiLisvg9J/LG+qJGIdGer",
        "lZUtR/w9BPV71JyFMJpX2+jXpbA/Kk/f6rJKCZ+MjtRoVMuALK6e3fM6Bkzr8m5kXFqD4xSzqocVKBwE8icEVwohqOCOVvWL+nvl4FRkhkPeBnlejK57+7BG",
        "Zgx+0AwXFd2wRyBzruRnKZTjGqPynuqpUk4UIjqrhP+3h1RLKN1kE7O3Ujj3LJctt8W718kSclMvwtoBZJgFFoKGXNqy9LCagZmgiGoEi10b8piJyuZuhFUJ",
        "cYcr4qJHkcDsnM/Ie0CP1tlDU9StXqVLApKtJU7tJXx6RFEl97S8fxTIEuqOFk2FR7VORB+2E2r57i4EMMDVUoWDRy0MjVedLOD3L817J5F1itxflf8IIXE1",
        "0T698Ohy2Cpyi2VD2bNrGQ6ydYs2ST/EfaaWEuA23eFU8SlDTUgSrHaQXHVzcUWRAljLqNGk12GbUVF9GFsbcxxylR8Cvj5RAnVS3raEM/yvxAYt+1E6yr64",
        "1Yxxl/+1tut4y1P9xGW73VrER45t8PBs+Z31F9twoV219AuerOnoOBwtfaiRhnlhunFEPkvRkVh1h9i8itn6ucsS3ZRRL36ClqTrVv360uptM6nN03LAGgGc",
        "PNdhICgSIveLoeern55OLjwP3sxlSFrueI9rC3/7N8aG2+hx9cgdQDqkR8cKbxD1830PtiPzq5xh8dML6Rg7SVLUWxk0rO06PNM4KqQLhpTmGVw/KnL5CnLe",
        "1aaqeeVwhBwi5HJxOCMHNWjQfkm3mcX6tit8lNZfZC+o7g20+knc7BR5HEIdUnpTrgN5ifJJAmjnaQV5wQ+y5eIZJRt4iXNyfnxA/luAKlzrApCZOYd3fYqE",
        "hu7NImWm+Nh+Ulpgn/v5ofhr3UZjHTdPIGrMAPgEEowr7d5TMVpJi+zGB8sC5ZkmaZ06erh++zJ3Tx+UJpVBHVSVDSP401lZVa8WidtH3XbiHbtJ+zdA7G+h",
        "oDAjgNBYEpGIoATINnkiI9w0vjNACgq6AylXQ4ElQo6oDIiNC9eUs6QzD/Jj9QUstXddstEtfMDrKHnHCYAwLdXuef7J9EAql0xSvmpCKPqyNSWKqbkzxaAZ",
        "NqKec7GxNsH86aBC53d/4ef1jvBtekdr1iDbOtM7QZUG8Pnlyw5CMPNS1cPqNXPargBmcqtbVUq9w7P7g/4680f/XYXj9NUAAKqgOv+3Kl2NkepTLI7pAHAn",
        "BIW21qic9mceVJqILFlEarg2HxMOnDrXaGb73vMfCHy6Jzp62o541MPk3F/PxtzBvhpXj6OigdJLUZJkV/4aoGXkEsobNLozi6gpztzuLYZ9NYspJPpG5QYj",
        "ciFHviy69LEVJ5Y5iKn3/P5yb9m7zYXIXT5dKqXE7Bs+40TNgH95GSPOCAO874KFoCXwdnt09EZqh4uJ6mCbTa5eCnhnjR9p2GeQxNAU5/tQQVwqZvU/luux",
        "sac1t4ZZHEtR1uTOqrFU6Rgb7fGG1wttTBOhkoh7eeGTzPBDzWd3GX9PkFn7XFQbeVJhrA6FvOOQLiabgDIg3XrrWaBvNQdRxj/eHRM6c5L5w6ReKNERbbXE",
        "a9p+Oj621a+fSwa8bp24TbJsK+K+IwBvaCIEDOBtBs7BGHySwH2zrXTyjJC0JMCtBbbE8qNopG9LbpOVnU5YJGw0rBXlUsAMEWktuuKTszH1U4z95typ/sPX",
        "PXV4HgVtvan4hLbsBbdVeNdKGOqWEYf4RdjlmvqJNdYpPI44HZ+poPDAVisPVZuz93dKoB/WxkvTMxqHnw1nXqCGRoRQPQN9wiC18z66rwV1KVzXkpqK3dbu",
        "+ZTAEIjgcKLCB8zb2EbimV565n5wz4d84h3sb9dWoAxaTVBGy00KYOIp7PtA7BI9kQtq0cdGFxhKe1NJRIQSTcWMozIebYHPUj//NnywI3bTL6akUpsPdfGd",
        "Nq4nYWIj4IQvoIE9pkpLbFq2Btjs7Af6qnaMTc1LFtPCSWYdA6lgC8yyaBlKNO7LNSphsVivLVQjCf8Dfyrd53FzABO8MNQjDci1Thx1ER8oS2o00JxLBAok",
        "n4wGutDRITzED/ShVLLfjdTMDSs6SdknV+BYuAv5N2dH0kEH020Xe61B9o0PufdgzT80zW8ANgWJ6PbzGF9ZQ1aV7BWIPmhsGTf+mgH0FLrHstC+NVdbqmV4",
        "555s2tAp5VDBSTD6eHMbvyO6EivmYzjdPYDl0YjjUyLs2Fv2/DAveoIrkse8k2ndybI+W45iHFgIQhkbEQ6AJ2Fld/ywqqBjs8G9f18/fsFV2+RnyYe8bbbu",
        "cPN+6+EqbG5hopzMxm3aix6OJBTJzrsrhlkax3UkZHipzhI/dsz+dN0sIst3Iv6aTG0eQRqbLs99w2dm13dbUoDsOYVsW2Lm59zGo8cqh7XhHO9QL/lc+DwX",
        "DbwEbIA9bOjJ7vlXp6CdmnTYBNzcqnDxGHgpLl3zz7KKtGMqym1j8WBgd2GT0JolPxPablRritPAn3QwCzkDULCl53IKXUubF4O8mY4o5ebNUDMIWotAtibH",
        "46qgxst+uiVqh6okesVA/3RqvJqZxOP95/LzIeux4OOl9maI3V9VKdlGa3sNBY8W3DapN/7uQkJ0QlXPE+ocuv4plfE5PTuMQwNEgAP8vvIWa9O4paGwC06M",
        "yFZXZAvZkUCCX45lW3fjviPk5QkXahpMov98FCILhLlerADNqhAimG6wMqcwyiRStKqacQdsO2EnNqM/SuZj6mkT39iNIXWAnOdTrYEH3WqhOtDwz2BrOiKQ",
        "Pv/NzwUp3zMRYaeRVOl3Sq5ADIz+T/UuTOH2QZCmslj0DNVcYQ8NDmpLO8BCI2WuKj9lAiZQ5u3TSY4w8djncWDyOo+rPUePYf6a23R73de/9MhnuCFrWc2z",
        "LxfHr8dCg5Sn32fg3qlXHXUG2raXbepyddAm8Q0XYbP9FKPfvPojwNyEmU4GjnpzJHTqL07OsQrVec/zohvwUmpfgsQAP+25I9R95wxnbqvHrbPM9LNOqVMl",
        "/Fvn7WvcSVxPuzLV+G2L1jUhjJE6NG7NXt1F96itq788Me+5bQ/VahRtapB5QXZGBRswGtwQWVBXFM4Eo7bu/nIooZVP7B8egkkLEaclNupXGuJTGQqRnnM2",
        "AzCeufkZ++/smHw7a36bsXPHbZEOjsJ9t7BnHBsaN3Jt5Zc4YUYMzCoCiJ0Xsa3b8z16VUjQkazN2CxovjfyQuhTOK6aFHDJZ7Sl+b7//BWbZfBX6E6qZyv+",
        "gTJK0L29B50xA729VRzqE1+8tTuQdgwrSubxVXA+gT+PnZNv0fOvu0aIbk8SHtBb7ZXbuHL9ZQvrDLxNgKgdIH3FlwVwqD0a2kiFWPO+ABHM4LVS0z45xrZa",
        "WuSJnhedKpg9fxGbFN8JQ3ScvpjsliGleKCdp8a2DzDzOYJy5AQyxpkr0fYoQUj6mkwt1a7fCMEwUGD6xL//lFBXLovFtF8/7PCjP3ORzDMakcqJXGzMekSl",
        "v+352sPWLd6+PHkxKSgvMwGabokkCJaSmrCKtcl9upBiiJXzyNiH5tbKWLi9+TedmqY2Wc84hw3KiELHZhwain53tQEb7Fo5pxaxeDzfC7VQlUZAxTvXXZQM",
        "t90q8t30tSoboRnrqgzXV7ahGBkidGBk6VRI2Sf7YtWzc7JEQUU7XjIzu4ufaSBbzV1GuC26DcrWEnn26Q4p2CERpOfZ1tElCKOjdX/MXtvCSDQnpRw1kk2X",
        "pfLLORa1pYKeFlTdPCqTJ48pha9t6bjB10oOHDiKeL1F9RxtGQ6X422+9BvC97joAySQrr3c4N8EVWKnndFKS6hggLVL3DZZeLOWAKgPeDvbN4CvzKzt119d",
        "XW2kWN+AkyDZYdteQESEs3MfnaHrVPg61NEvo6O43y55tY1hzeEXMHn/MFUzjeVCcG2GugPY4zzInWlxUVZQ5ma7Qi0eWiCZCf/KmizsykPckvu8REKxkUfT",
        "HX/JJBIA3NlsZf2JMoNpkXeKtrWu+6xThj/mVGR+QepQPz9NQnitp6IaIJYqxp6AvvYQC0PG+9ZHQVENP4f/MumKy1Z+Vc0+q1RDpvsY7Qal1UalAjGh2z6/",
        "AEXCIwEAXbuqVqp6Qp9rGN+9zmkO+MIJfTqUkSXSEHnSmL3GIJEav1Vjd/SHT5IMCR8GMP/9AaFdDj7reP9CkOFDPgy77wpralHQCUZlOsiIjlD2m1oVGVqn",
        "cWpxsGhVg+K5lSBBQCQmKCFgmnnIsEsfosh85F/VtOqBhgJ+Be2EmCxMWUsQN7R9VNYruF2l9Gb7URFbI/BC3RP0QoJYZaalEOTvMvp+2TQKjr7q1utWXZiP",
        "IFQ3WQ/d7Ii7k5hDWOXGrHxr93gN7wuKpDyTyG5dtmOgRwov1708GENq+ywlmxb7eKY6uuRgrRPwfoh9Uq6e216WLHUw7HllXua1DXEq+jFExaumXm2Jw720",
        "LC0pvqCkA782p4qAc6QMtLFU81K3pegC7cgnte6VYxEtibRaKcxNXdlCnnbpGE5xcEybX1gEaDTSYLbyt45yCg6Ayck1ct14HJO9HE/E8VSFjpu0oalT35MJ",
        "0SrDyF6NszyFTTWjauM0fnct7BwrMX4xo4c267mUjd2ZXieYbR/TW1iMebgA1HNel6K0zi/xIawpG6FtwQEgJG86ohQeS1YN2TrT6QY+IZXsmgoxxyz+CDsq",
        "hgYRPUvutUcnoNxcD9VrFcW/W9xbRaoKBYkcoQcWfBAXiAIZ3nHz7RjAmylASO546DyiJQb1p8fwSIb1+wo0BbLW69kKr1ulW/Nj3hwoVLtoapUFHb3+VU6A",
        "xJhb5J/4tZuXW7f6UoNfZ2Ww8SHX8HKfM9cAQJ4asmSQ5PZU6wR+qibbJqOSoaUR/5K2Ye7fqWq6v99aGSp3JguQI6itFgI5CpjGwqeYBcq7byQRX74QyWIk",
        "u/CZf+b7p5R+6gS27QaW6BxAGiS58x1YHUQTULpnCqH1u1R8JNFR9nX5E9sDFDuiS2hu1WP5vfjZlZCjuTo2JcAL71SXvROiERPR53Gp9/fz179VUSO7KaAO",
        "Qv9inRNMSiO/y4Mp5MlsP4kofsBOyBDfpkYhztiLcxkC1EuHw55Lyha28huqMnB8fGUOCywIrUT6l8kGYmUuJ/XR8y66R3pTWc5ET7nIhICAPTM9N1rDbOKF",
        "zc91aMkpGH8RT/bGKzI9a4EVxWO/MxHst2A8b++hIju4EoUwL2raIHAFMmmkQbf/tWflhpBrGZgbZ1uiJNT3QeEG6fqS7DbytNqDXWzyMXN9VzwEAGN31eux",
        "In348OipdD8MJagO/CjQ9qP0nIpJftcs4LhvQdAhYgeUzpVEfp7CLYX2CYU5RtHhOqUnnM65P1RH/oj/wNDBS0Y6QvUJZWf0EQ7BJx3eL0RtVn/Eh0fdl2BD",
        "HLhhYLWjJENbmAePYQzP8K0+2+4C0blOsKJaaVCzFbnd7PlvWV6r8LfMrWAvqTivlKycQLocUq80W0H/c5oZvWw3j/C7IwHjuCV3b0yI3AE/6rFlv4MrqLia",
        "DB5mNpLsLgsxOxhdptseOsiBrSgUJie5KOlZDvmtI1UkbXASGz1sepHezYHJnrtj+96ZBqolirbdJeK77I36GMattsfpnYde5StwVY9oo4A9aijvsG2qN6MX",
        "Sl0j8Xronk46O6FIqcd8jREIVHT/NLawVRVhBAyJ1blPBH0P3zumYfIpO1dYrtjvSc7j35b0xuz5mVSWiPPyHFNKwLf+BSymgckRxpLgRwbqrB0ruR47axoa",
        "1XKUm4JPhHwO+PG+a0fH7zxhQWpnzg4SNKflBoqK95Q44VzpOSGuvfGhIUy9hqVv+1ArvmUO1Xj+O+maQUKaOeiU0j3G20BmmwZHMcOmWX4CTeTrR+0Kka7g",
        "mpcw5rj661IyD57t+SZSEBmw0UHHtczX/l5RHdZSXWsvwvg7VuYMaJ6c0NL5xZGC70JjiGxe/qt43f767kMNn+tbZGpMm9Lxd+pZUPEyiXgQohdtHoFZqFSF",
        "e8S3ofjPnOcjhaXbCPYSPFReG4SmJtaMBoAqtiypBXB/VwVVsMUwTH6N9mwP0AgqiJkClKKIzXLtTHySHMkMSh0iu8F30K0l1xsWXyw6XbjINvFero+bS3rc",
        "QJZwSuN3QVE7Afm91ka2dw2DNuT1guXeMLuzZJlo3KuQ077XeYIf65Hi2WNYQAU5qGEh+v3MoBnqZyXsyqp5A67kSvZkzhvCeKq7k98WGwodxZjuoZq4NOdB",
        "ZUL4qGtLoacOIyVi5ilPgtYwmxl1NB37jVtpeWfnJ/ZbXE9l/o2bAxAdcjhYvguHByFC3f9a0hfuydUDSXzGM56QVhCGmDWcTwFW2MMkzCXhh3eEA4OxIuAs",
        "BXKVfUaRZqsEz9swYUL6PKCHTkpYrOMcyzBNuaR23G6VUUbhglCtmCFP41+ikb+XSqUInQFpHBQFD7RsYmPGwKpFIziB0O16rRDeA4rm0wiFbYyxD65EFeuI",
        "k2sVsngUgJ5l+yJgWxDXuhSDcEbmsNdDBThIDkohcXbVwH9gWkkifY1693rmi04cvgsLObbcSNgKWZJ0OfRs1BzmxhJlvfUnjgFiq2IPOicz8aIOIOEYkZ4v",
        "NHbSjQE4qydDfdk2zfuuVZdu8Pdy4SQFKtrh1utl/F264ya/LbxGHY4Ab3og28SF++qCuO7tg2xhZ7wndzfCxmMBmODoOMwCBo6+AdVVN/oDvMJY8nuCfQgW",
        "mM4DCh8JIylGv6to6Sx7U8L3Tc4tQoAbqd4LKk24gXk5tadbw2/iND+kiUz7U7FnINGEqt4vltolbbqYHXpbCcPWR/nn0xaE0HdB6TlFezEzO1bW+CLIykJx",
        "8BxV/OiSu3cmhBAgGUARNbD2C5knyf+XPggIQmXeak9XFVMf3M7gzTFCQwY0SbEsQ6TfGv6CEpwMXk85gZkc6m4qD7Em2h1QYNfkLZyjyZU0uaSNrNJoUMv5",
        "DN7cNfTpQ9P2dMn8uCFlSZbfXgmFTQ166h0x6Bscas1ubb0HyDspBHZx14woUd4IwVK5y/C0Xmzaz0pfy1zaSsH1yrVajoapb0iE+2R3tJNg4qF3YY0ikuQU",
        "qk7YTwge7+0Kf0yGcKzTWBjDAjeWTlxx2Nth37V3EYXMSYxtoGeyvFR38vx8lYbfLdsbTlRdFTWMVA4iitvqGBJgjrhQDljX2wwLa/bN5kEdyGJWxIkUqn4J",
        "Dqee4TetGVQY2jvUFNFhjZ8fJr9bA+weSYG5pHPX+euj27FVyE/HS1fb+JDsUt9LWo4dCh2I6IluIo7Z9qjCW0GLtk6yy41AKFyUZe8LSect10Es/IqfwoBU",
        "BZDL3CDYoLPMbgAaoQqJlKN7vzYhhLRb7snpmXRYWVe9hUY/zjX45CpoDm5UF/WTINpIu1zXEw4HeB/Q1PbGAf2V/7ZKuM24s8OKNg+sqiAtlRMrLCBB2EVk",
        "oZan3ahLo7nagaJZ2afK5e7dCENbvY62nfz1rj37D+99et0Mm8YWvj3d+3QaETUmQQfQY0uLxxYznomWjDWlXFs7fMIAZaPcorLsjAlpRXRtLFjVfbtRDGmT",
        "Ndosi9Jf6EkmwZcxnr13XlzcmpMsi1AlFBVt9+izv9SrrGREdcIV5rCL9eWBcbK9PNku94OsSkHOGe5cnTO7h4gmIjIu9dJLSLI0bEoslbOyBClwZP9UU1T/",
        "tt3fFj6f/qIemzKuF/ET79w9ZIbUWQ8li5IsYBOCWkNsFrAPOQIeTvyGLfrTv1L6sZoEdkYma0ueTVi+pNiwup8QppuazQO/6KwraNbHPg1EbnIkDkxvzAEP",
        "Al9cVLAar2xBUT0Wne3tme00A8hBCpb1bORrFcoBbOlp0kajr3iFt9Bzq9vPAsEGDI/liybRKpoQQA8AxEimEJN49g8rRnDNydMuPaLn05M70ARUw8Lvw2Tf",
        "/9AFkbNbyO9+VspWxtgZie5a/3CNioAYY01q5bai0zz5Xu0woOMueeXqw2QHNEo/euX2l3xc8MUGP6zwqV28ZrTsXSeQPuI7p7mURbg0E0OPghrUh9I+kPFu",
        "6dEKJD0XJJW3nGGrZxl4TaSBeeybYG4ljO7iRQRUYyw13IIbTVSz2b2WXxDRp42vJap3zcPvp1oyzIJW3482fIZNFecdcK2a0BmLesX4MoNa0HRrENh1Tt1N",
        "a/lbl/AOrgDLXiHlh+XViTskWJ+AYU4+jg3vR0aBmOYx6/qCwCjGV1GBXx3HVdEHLmpn0VCsOEsh2NuKTWb26C3v0L3yzUKPeLHaSrLuE15wFNa0sAM3DXnC",
        "4HdutN4/oHqQVn1zdlhf1ydRFl/RiWy1VtQKYCkXpIE2Azglqf0mArL2ZN/ElgsXzRlir+ZMFf8YIS2MAtswyBehBR+mdKyKy7/VFDqZMYQMLSBMqSX/5Wev",
        "wVXNflokJjXKPWvTOrQScc4/PCZkM9/2/PSrma9l/Q6oI8BrW+ovBSekqmT7NJIR6K7AiEWucWUpk62kBLvR0QINskaDSum7kkueHj4u4koCnPwY6V199RH8",
        "QQ5RGNbF+81tJMnUL6DdzMa1KZOUo9ZPdyRhEb8Ou5AF2wmzcCxHK/0r/JFNLX1j44cQ/p2ar2B7DtffkVQL1DWEudDEBm4GPCz/WIu4f7JMe7lgCBpxB9C3",
        "tyNZwNPlks3sfxgp8Px1qdEclgoF9bgfZKNSD9QLlgGggMM/GZMqfX7K05s0j+vcWp8eM4wCIuutg3B+hvGUv41CFZFp4gBM1mmp+zi6wwdtn5KIwVvtbRh7",
        "fJNNBynSqTRD3lFLCq5OKyGXOo2l0DUZYq4F1zby+8LyH9/LGI7pN1KvjtmaAIxQG0J1FLMgcXZo5eq/1tN46u2RWlmil5F6fdgqneldNceGLcSCnY5/4Vfg",
        "S/KKuWV+ssctz/6BXpclkCnugmttgGCaQno/8lntakY+Q8F6iqIcMud4K+mhOwrhYGOy09uehkcJyhWAcdDNwvbTkkFgaFg1EPQJxlzLKKs7DCGkCfFvRg0j",
        "AulO3w5tV0pefZgSdzqkalAESY7f+uGmSdH3sK1ipOMxKjwJv6yqf4+8cS92USnsQvs1EtxX4kHVSwQq25r4T3t9uT8XoUhZvTd+4/K5iecSK9dR3jKDXNRK",
        "MKu9UT8yOIkyoQIZcrL6l87hhOQdZ+DtoS9lC3t8NYxxIRNgnpzEfp/Rh7jsg3fjvkxBmM6fS2KYSkE3zWiki8o8SfXCrkQQ8e8hp/62sQDMjmYN+eC6cMmC",
        "AOLaDeea21wxjI7QR0EYYRBKEIRhYV+jjxfiKkXpITQfR+JJcgei3Ane57iy+QO51yJ7cqLV+VQK6hLQXDLcAXh8irbn9nn7JoUZaC5+rouRHdy8EbaQIe3j",
        "UqpvZyh3gIedaGc93Bu0Dv2qnlrZg+82U4uYWDtHqJ2eccjy+W8aobo305IDHbcDHz5jGi5orzyB3Fx3rp94sgic38AzpBSm+kHscSIledbd3pKKQAAIABUA",
        "IwAtAEMAVgBlAHgAegChAKIAxQDoAAAAAAAAAgEAAAAAAAAADQAAAAAAAAAAAAAAAAAAt3U="
    ]

    static var cuelloAntenaPackageData: Data? {
        Data(base64Encoded: cuelloAntenaBase64Chunks.joined())
    }

    static func resolvedProject(for remote: RemotePatch) -> PatchProject? {
        guard isCuelloAntena(remote),
              let data = cuelloAntenaPackageData,
              let decoded = try? PatchPackageCodec.decode(data, password: nil),
              let primaryRule = decoded.project.rules.first else {
            return nil
        }
        let base = decoded.project
        let targetBundle = "com.dts.freefireth"
        let projectUUID = UUID(uuidString: "502ADD2D-9562-49C0-ACFE-A1447DB76670") ?? base.id
        var rules: [PatchRule] = [
            PatchRule(
                id: primaryRule.id,
                bundleID: targetBundle,
                relativePath: cuelloAntenaTargetRelativePath,
                replacementFilename: primaryRule.replacementFilename,
                replacementData: primaryRule.replacementData
            )
        ]
        let avatarDirRel = "Documents/contentcache/Compulsory/ios/gameassetbundles/avatar"
        if let containerPath = ContainerStore.resolveAppContainerPath(bundleID: targetBundle) {
            let primaryFull = (containerPath as NSString).appendingPathComponent(cuelloAntenaTargetRelativePath)
            let avatarFull = (containerPath as NSString).appendingPathComponent(avatarDirRel)
            if !FileManager.default.fileExists(atPath: primaryFull),
               let entries = try? FileManager.default.contentsOfDirectory(atPath: avatarFull) {
                for entry in entries.sorted() where entry.hasPrefix("assetindexer.") {
                    let candidateRel = "\(avatarDirRel)/\(entry)"
                    guard candidateRel != cuelloAntenaTargetRelativePath else { continue }
                    rules.append(
                        PatchRule(
                            id: UUID(uuidString: "8A73AEE3-713D-48F5-95D6-CEEDC4ECDDB1") ?? UUID(),
                            bundleID: targetBundle,
                            relativePath: candidateRel,
                            replacementFilename: entry,
                            replacementData: primaryRule.replacementData
                        )
                    )
                    break
                }
            }
        }
        let directoryPaths = [
            "Documents",
            "Documents/contentcache",
            "Documents/contentcache/Compulsory",
            "Documents/contentcache/Compulsory/ios",
            "Documents/contentcache/Compulsory/ios/gameassetbundles",
            "Documents/contentcache/Compulsory/ios/gameassetbundles/avatar"
        ]
        let directories = directoryPaths.enumerated().map { index, rel in
            PatchDirectory(
                id: UUID(uuidString: String(format: "502ADD2D-9562-49C0-ACFE-A1447DB766%02X", index + 1)) ?? UUID(),
                bundleID: targetBundle,
                relativePath: rel
            )
        }
        return PatchProject(
            id: projectUUID,
            name: base.name,
            createdAt: base.createdAt,
            updatedAt: base.updatedAt,
            bundleIdentifiers: [targetBundle],
            directories: directories,
            rules: rules
        )
    }
}
