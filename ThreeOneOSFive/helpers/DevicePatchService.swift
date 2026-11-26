import Foundation

enum DevicePatchService {
    static func apply(project: PatchProject) throws -> PatchTransactionReceipt {
        let bundleIDs = orderedBundleIdentifiers(in: project)
        return try withResolvedContainers(bundleIDs: bundleIDs) { roots in
            try PatchTransaction.apply(
                project: project,
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

            if let targetRoot = roots[targetBundleID], !targetPaths.isEmpty {
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

        for bundleID in bundleIDs {
            guard let path = ContainerStore.resolveAppContainerPath(bundleID: bundleID),
                  ContainerStore.isApplicationContainerPath(path) else {
                throw PatchPackageError.targetAppUnavailable(bundleID)
            }
            roots[bundleID] = PatchPathValidator.canonicalFileURL(URL(fileURLWithPath: path, isDirectory: true))
        }
        return try operation(roots)
    }
}
