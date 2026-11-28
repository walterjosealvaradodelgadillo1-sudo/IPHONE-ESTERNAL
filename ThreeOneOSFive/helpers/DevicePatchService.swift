import CryptoKit
import Foundation

enum DevicePatchService {
    private static let avatarRelativeDir = "Documents/contentcache/Compulsory/ios/gameassetbundles/avatar"

    static func apply(project: PatchProject) throws -> PatchTransactionReceipt {
        let bundleIDs = orderedBundleIdentifiers(in: project)
        return try withResolvedContainers(bundleIDs: bundleIDs) { roots in
            let expandedProject = expandAvatarAssetIndexerRules(in: project, roots: roots)
            return try PatchTransaction.apply(
                project: expandedProject,
                backupRoot: try PatchProjectLibrary.backupRootURL(),
                containerResolver: { bundleID in
                    guard let root = roots[bundleID] else {
                        throw PatchPackageError.targetAppUnavailable(bundleID)
                    }
                    return root
                }
            )
        }
    }

    static func restore(receipt: PatchTransactionReceipt) throws {
        let bundleIDs = try PatchTransaction.requiredBundleIdentifiers(for: receipt)
        try withResolvedContainers(bundleIDs: bundleIDs) { roots in
            try PatchTransaction.restore(
                receipt: receipt,
                containerResolver: { bundleID in
                    guard let root = roots[bundleID] else {
                        throw PatchPackageError.targetAppUnavailable(bundleID)
                    }
                    return root
                }
            )
            // Remote-only packages must not leave original backups or journals
            // behind after a successful CLEAN/restore.
            try? PatchTransaction.discardBackup(for: receipt)
        }
    }

    static func restoreAll(
        projectID: UUID?,
        project: PatchProject? = nil,
        targetBundleID: String,
        fallbackTargetPaths: [String] = []
    ) throws {
        let backupRoot = try PatchProjectLibrary.backupRootURL()
        var targetPaths = Set<String>(fallbackTargetPaths)
        if let project {
            for rule in project.rules where rule.bundleID == targetBundleID || project.allBundleIdentifiers.contains(targetBundleID) {
                targetPaths.insert(rule.relativePath)
            }
        }

        let receipts = PatchTransaction.allActiveReceipts(
            projectID: projectID,
            backupRoot: backupRoot,
            targetBundleID: targetBundleID,
            targetRelativePaths: targetPaths
        )

        var requiredBundles = Set<String>([targetBundleID])
        for receipt in receipts {
            if let bundles = try? PatchTransaction.requiredBundleIdentifiers(for: receipt) {
                requiredBundles.formUnion(bundles)
            }
        }

        try withResolvedContainers(bundleIDs: Array(requiredBundles)) { roots in
            var firstError: Error?
            for receipt in receipts {
                do {
                    try PatchTransaction.restore(
                        receipt: receipt,
                        containerResolver: { bundleID in
                            guard let root = roots[bundleID] else {
                                throw PatchPackageError.targetAppUnavailable(bundleID)
                            }
                            return root
                        }
                    )
                    try? PatchTransaction.discardBackup(for: receipt)
                } catch {
                    if firstError == nil {
                        firstError = error
                    }
                }
            }

            if let targetRoot = roots[targetBundleID] {
                let avatarURL = targetRoot.appendingPathComponent(avatarRelativeDir, isDirectory: true)
                let hAvatar = ContainerStore.grantContainerAccess(avatarURL.path)
                defer { if hAvatar >= 0 { bad_query_release(hAvatar) } }
                if let entries = try? FileManager.default.contentsOfDirectory(atPath: avatarURL.path) {
                    for entry in entries where entry.hasPrefix("assetindexer.") && !entry.hasPrefix(".3105-") {
                        let rel = "\(avatarRelativeDir)/\(entry)"
                        targetPaths.insert(rel)
                        _ = ContainerStore.grantContainerAccess(avatarURL.appendingPathComponent(entry).path)
                    }
                }
                if !targetPaths.isEmpty {
                    do {
                        try PatchTransaction.ensureOriginalsRestored(
                            bundleID: targetBundleID,
                            relativePaths: Array(targetPaths),
                            backupRoot: backupRoot,
                            containerRoot: targetRoot
                        )
                        firstError = nil
                    } catch {
                        if firstError == nil {
                            firstError = error
                        }
                    }
                }
            }

            if let firstError {
                throw firstError
            }
        }
    }

    static func latestReceipt(projectID: UUID, targetBundleID: String? = nil) -> PatchTransactionReceipt? {
        guard let backupRoot = try? PatchProjectLibrary.backupRootURL() else { return nil }
        return PatchTransaction.latestReceipt(
            projectID: projectID,
            backupRoot: backupRoot,
            targetBundleID: targetBundleID
        )
    }

    private static func orderedBundleIdentifiers(in project: PatchProject) -> [String] {
        project.allBundleIdentifiers
    }

    private static func withResolvedContainers<T>(
        bundleIDs: [String],
        operation: ([String: URL]) throws -> T
    ) throws -> T {
        var roots: [String: URL] = [:]
        var transientHandles: [Int64] = []
        defer {
            for h in transientHandles where h >= 0 {
                bad_query_release(h)
            }
        }

        let subpathsToUnlock = [
            "Documents",
            "Documents/contentcache",
            "Documents/contentcache/Compulsory",
            "Documents/contentcache/Compulsory/ios",
            "Documents/contentcache/Compulsory/ios/gameassetbundles",
            "Documents/contentcache/Compulsory/ios/gameassetbundles/avatar",
            "Documents/contentcache/Optional",
            "Documents/contentcache/Optional/ios",
            "Documents/contentcache/Optional/ios/gameassetbundles"
        ]

        for bundleID in bundleIDs {
            guard let path = ContainerStore.resolveAppContainerPath(bundleID: bundleID),
                  ContainerStore.isApplicationContainerPath(path) else {
                throw PatchPackageError.targetAppUnavailable(bundleID)
            }
            let canonicalRoot = PatchPathValidator.canonicalFileURL(URL(fileURLWithPath: path, isDirectory: true))
            _ = ContainerStore.grantContainerAccess(path)
            _ = ContainerStore.grantContainerAccess(canonicalRoot.path)
            for sub in subpathsToUnlock {
                let subURL = canonicalRoot.appendingPathComponent(sub, isDirectory: true)
                let h = ContainerStore.grantContainerAccess(subURL.path)
                if h >= 0 { transientHandles.append(h) }
            }
            roots[bundleID] = canonicalRoot
        }
        return try operation(roots)
    }

    private static func expandAvatarAssetIndexerRules(
        in project: PatchProject,
        roots: [String: URL]
    ) -> PatchProject {
        var expandedRules = project.rules
        var existingKeys = Set(
            expandedRules.map { "\($0.bundleID.lowercased())::\($0.relativePath)" }
        )

        for rule in project.rules {
            guard let root = roots[rule.bundleID] else { continue }
            let targetFileURL = root.appendingPathComponent(rule.relativePath)
            _ = ContainerStore.grantContainerAccess(targetFileURL.deletingLastPathComponent().path)
            _ = ContainerStore.grantContainerAccess(targetFileURL.path)

            guard rule.relativePath.hasPrefix(avatarRelativeDir + "/") else { continue }
            let avatarURL = root.appendingPathComponent(avatarRelativeDir, isDirectory: true)
            _ = ContainerStore.grantContainerAccess(avatarURL.path)
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: avatarURL.path) else {
                continue
            }
            for entry in entries.sorted() where entry.hasPrefix("assetindexer.") && !entry.hasPrefix(".3105-") {
                let candidateRel = "\(avatarRelativeDir)/\(entry)"
                let key = "\(rule.bundleID.lowercased())::\(candidateRel)"
                let entryURL = avatarURL.appendingPathComponent(entry)
                _ = ContainerStore.grantContainerAccess(entryURL.path)
                guard existingKeys.insert(key).inserted else { continue }
                expandedRules.append(
                    PatchRule(
                        id: deterministicRuleUUID(bundleID: rule.bundleID, relativePath: candidateRel),
                        bundleID: rule.bundleID,
                        relativePath: candidateRel,
                        replacementFilename: entry,
                        replacementData: rule.replacementData
                    )
                )
            }
        }

        guard expandedRules.count != project.rules.count else { return project }
        return PatchProject(
            id: project.id,
            name: project.name,
            createdAt: project.createdAt,
            updatedAt: project.updatedAt,
            bundleIdentifiers: project.bundleIdentifiers,
            directories: project.directories,
            rules: expandedRules
        )
    }

    private static func deterministicRuleUUID(bundleID: String, relativePath: String) -> UUID {
        let seed = Array(SHA256.hash(data: Data("\(bundleID)|\(relativePath)".utf8)).prefix(16))
        var bytes: uuid_t = (
            seed[0], seed[1], seed[2], seed[3],
            seed[4], seed[5],
            (seed[6] & 0x0F) | 0x40, seed[7],
            (seed[8] & 0x3F) | 0x80, seed[9],
            seed[10], seed[11], seed[12], seed[13], seed[14], seed[15]
        )
        return withUnsafePointer(to: &bytes) {
            $0.withMemoryRebound(to: uuid_t.self, capacity: 1) { UUID(uuid: $0.pointee) }
        }
    }
}
