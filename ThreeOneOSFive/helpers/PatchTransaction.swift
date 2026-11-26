import CryptoKit
import Darwin
import Foundation

struct PatchTransactionReceipt: Equatable, Identifiable {
    let id: UUID
    let projectID: UUID
    let journalURL: URL
}

enum PatchTransaction {
    private enum Status: String, Codable {
        case prepared
        case applied
        case rolledBack
        case restored
    }

    private struct Record: Codable {
        let ruleID: UUID
        let bundleID: String
        let relativePath: String
        let containerFingerprint: Data
        let originalExisted: Bool
        let backupFilename: String?
        let originalDigest: Data?
        let replacementDigest: Data
    }

    private struct DirectoryRecord: Codable {
        let bundleID: String
        let relativePath: String
        let containerFingerprint: Data
    }

    private struct Journal: Codable {
        let schemaVersion: Int
        let transactionID: UUID
        let projectID: UUID
        let createdAt: Date
        var status: Status
        let records: [Record]
        let createdDirectories: [DirectoryRecord]?
    }

    private struct ResolvedRule {
        let rule: PatchRule
        let containerRoot: URL
        let target: URL
    }

    private struct ResolvedDirectory {
        let bundleID: String
        let relativePath: String
        let containerRoot: URL
        let target: URL
    }

    private static let schemaVersion = 1
    private static let journalFilename = "journal.plist"
    private static let originalVaultDirectoryName = "OriginalVault"

    private struct OriginalVaultMetadata: Codable {
        let bundleID: String
        let relativePath: String
        var originalExisted: Bool
        var originalDigest: Data?
        var posixPermissions: Int?
        var protectionType: String?
        var knownReplacementDigests: [Data]
    }

    static func apply(
        project: PatchProject,
        backupRoot: URL,
        containerResolver: (String) throws -> URL,
        beforeWrite: ((Int) throws -> Void)? = nil,
        fileManager: FileManager = .default
    ) throws -> PatchTransactionReceipt {
        guard !project.rules.isEmpty || !project.directories.isEmpty else {
            throw PatchPackageError.invalidProject
        }

        var roots: [String: URL] = [:]
        var resolvedRules: [ResolvedRule] = []
        var resolvedDirectories: [ResolvedDirectory] = []
        var targetKeys = Set<String>()

        func resolvedRoot(for bundleID: String) throws -> URL {
            if let cached = roots[bundleID] { return cached }
            let root = PatchPathValidator.canonicalFileURL(try containerResolver(bundleID))
            roots[bundleID] = root
            return root
        }

        var requestedDirectories = Set<String>()
        for directory in project.directories {
            let bundleID = try PatchPathValidator.canonicalBundleIdentifier(directory.bundleID)
            guard bundleID == directory.bundleID else { throw PatchPackageError.invalidProject }
            requestedDirectories.insert(bundleID + "\0" + directory.relativePath)
        }
        for rule in project.rules {
            let components = try PatchPathValidator.canonicalRelativePath(rule.relativePath)
                .split(separator: "/").map(String.init)
            guard components.count > 1 else { continue }
            for count in 1..<components.count {
                requestedDirectories.insert(
                    rule.bundleID + "\0" + components.prefix(count).joined(separator: "/")
                )
            }
        }

        for key in requestedDirectories.sorted(by: directoryKeySort) {
            let parts = key.split(separator: "\0", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { throw PatchPackageError.invalidProject }
            let bundleID = try PatchPathValidator.canonicalBundleIdentifier(String(parts[0]))
            let relativePath = try PatchPathValidator.canonicalRelativePath(String(parts[1]))
            let root = try resolvedRoot(for: bundleID)
            let target = try PatchPathValidator.resolveContainedTargetURL(
                relativePath: relativePath,
                containerRoot: root
            )
            try validateDirectoryTarget(
                target,
                relativePath: relativePath,
                containerRoot: root,
                fileManager: fileManager
            )
            resolvedDirectories.append(ResolvedDirectory(
                bundleID: bundleID,
                relativePath: relativePath,
                containerRoot: root,
                target: target
            ))
        }

        for rule in project.rules {
            let bundleID = try PatchPathValidator.canonicalBundleIdentifier(rule.bundleID)
            guard bundleID == rule.bundleID else { throw PatchPackageError.invalidProject }
            let root = try resolvedRoot(for: bundleID)
            let target = try PatchPathValidator.resolveContainedTargetURL(
                relativePath: rule.relativePath,
                containerRoot: root
            )
            let targetKey = target.path
            guard targetKeys.insert(targetKey).inserted else {
                throw PatchPackageError.duplicateTarget
            }
            try validateFileTarget(
                target,
                relativePath: rule.relativePath,
                containerRoot: root,
                allowMissingParents: true,
                fileManager: fileManager
            )
            resolvedRules.append(ResolvedRule(rule: rule, containerRoot: root, target: target))
        }

        let transactionID = UUID()
        let transactionDirectory = backupRoot
            .appendingPathComponent(project.id.uuidString, isDirectory: true)
            .appendingPathComponent(transactionID.uuidString, isDirectory: true)
        do {
            try fileManager.createDirectory(
                at: transactionDirectory,
                withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.complete]
            )
        } catch {
            throw PatchPackageError.applyFailed
        }

        var records: [Record] = []
        let createdDirectories = resolvedDirectories.compactMap { resolved -> DirectoryRecord? in
            guard !fileManager.fileExists(atPath: resolved.target.path) else { return nil }
            return DirectoryRecord(
                bundleID: resolved.bundleID,
                relativePath: resolved.relativePath,
                containerFingerprint: containerFingerprint(resolved.containerRoot)
            )
        }
        do {
            for resolved in resolvedRules {
                let replacementDigest = digest(resolved.rule.replacementData)
                let vaultEntry = try captureOriginalInVaultIfNeeded(
                    bundleID: resolved.rule.bundleID,
                    relativePath: resolved.rule.relativePath,
                    targetURL: resolved.target,
                    replacementDigest: replacementDigest,
                    backupRoot: backupRoot,
                    fileManager: fileManager
                )
                let existed = vaultEntry.originalExisted
                let backupFilename = existed ? "\(resolved.rule.id.uuidString).original" : nil
                var originalDigest: Data?
                if let backupFilename {
                    let backupURL = transactionDirectory.appendingPathComponent(backupFilename)
                    let sourceForBackup = vaultEntry.originalFileURL ?? resolved.target
                    try fileManager.copyItem(at: sourceForBackup, to: backupURL)
                    try fileManager.setAttributes(
                        [.protectionKey: FileProtectionType.complete],
                        ofItemAtPath: backupURL.path
                    )
                    originalDigest = try digestFile(backupURL)
                }
                records.append(Record(
                    ruleID: resolved.rule.id,
                    bundleID: resolved.rule.bundleID,
                    relativePath: resolved.rule.relativePath,
                    containerFingerprint: containerFingerprint(resolved.containerRoot),
                    originalExisted: existed,
                    backupFilename: backupFilename,
                    originalDigest: originalDigest,
                    replacementDigest: replacementDigest
                ))
            }
        } catch let error as PatchPackageError {
            throw error
        } catch {
            throw PatchPackageError.applyFailed
        }

        let journalURL = transactionDirectory.appendingPathComponent(journalFilename)
        var journal = Journal(
            schemaVersion: schemaVersion,
            transactionID: transactionID,
            projectID: project.id,
            createdAt: Date(),
            status: .prepared,
            records: records,
            createdDirectories: createdDirectories
        )
        do {
            try writeJournal(journal, to: journalURL)
        } catch {
            throw PatchPackageError.applyFailed
        }

        do {
            for resolved in resolvedDirectories where !fileManager.fileExists(atPath: resolved.target.path) {
                try fileManager.createDirectory(
                    at: resolved.target,
                    withIntermediateDirectories: false
                )
            }
            for (index, resolved) in resolvedRules.enumerated() {
                try beforeWrite?(index)
                try atomicWrite(
                    resolved.rule.replacementData,
                    to: resolved.target,
                    preservingExistingAttributes: true,
                    fileManager: fileManager
                )
                guard try digestFile(resolved.target) == records[index].replacementDigest else {
                    throw PatchPackageError.applyFailed
                }
            }
            journal.status = .applied
            try writeJournal(journal, to: journalURL)
            return PatchTransactionReceipt(
                id: transactionID,
                projectID: project.id,
                journalURL: journalURL
            )
        } catch {
            do {
                try restoreRecords(
                    records,
                    transactionDirectory: transactionDirectory,
                    roots: roots,
                    requirePatchedDigest: false,
                    createdDirectories: createdDirectories,
                    fileManager: fileManager
                )
                journal.status = .rolledBack
                try writeJournal(journal, to: journalURL)
            } catch {
                // Preserve the prepared journal and backups for explicit recovery.
            }
            throw PatchPackageError.applyFailed
        }
    }

    static func restore(
        receipt: PatchTransactionReceipt,
        containerResolver: (String) throws -> URL,
        fileManager: FileManager = .default
    ) throws {
        var journal: Journal
        do {
            journal = try readJournal(receipt.journalURL)
        } catch {
            throw PatchPackageError.restoreFailed
        }
        guard journal.schemaVersion == schemaVersion,
              journal.transactionID == receipt.id,
              journal.projectID == receipt.projectID,
              journal.status == .applied || journal.status == .prepared
        else {
            throw PatchPackageError.restoreFailed
        }

        var roots: [String: URL] = [:]
        do {
            for record in journal.records where roots[record.bundleID] == nil {
                let root = PatchPathValidator.canonicalFileURL(try containerResolver(record.bundleID))
                roots[record.bundleID] = root
            }
            for directory in (journal.createdDirectories ?? []) where roots[directory.bundleID] == nil {
                let root = PatchPathValidator.canonicalFileURL(try containerResolver(directory.bundleID))
                roots[directory.bundleID] = root
            }
            try restoreRecords(
                journal.records,
                transactionDirectory: receipt.journalURL.deletingLastPathComponent(),
                roots: roots,
                requirePatchedDigest: false,
                createdDirectories: journal.createdDirectories ?? [],
                fileManager: fileManager
            )
            journal.status = .restored
            try writeJournal(journal, to: receipt.journalURL)
        } catch {
            throw PatchPackageError.restoreFailed
        }
    }

    static func allActiveReceipts(
        projectID: UUID?,
        backupRoot: URL,
        targetBundleID: String? = nil,
        targetRelativePaths: Set<String> = [],
        fileManager: FileManager = .default
    ) -> [PatchTransactionReceipt] {
        var projectDirectories: [URL] = []
        if let projectID {
            let direct = backupRoot.appendingPathComponent(projectID.uuidString, isDirectory: true)
            if fileManager.fileExists(atPath: direct.path) {
                projectDirectories.append(direct)
            }
        }
        if !targetRelativePaths.isEmpty || projectDirectories.isEmpty {
            let allDirs = (try? fileManager.contentsOfDirectory(
                at: backupRoot,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            )) ?? []
            for dir in allDirs where dir.lastPathComponent != originalVaultDirectoryName {
                if !projectDirectories.contains(where: { $0.standardizedFileURL == dir.standardizedFileURL }) {
                    projectDirectories.append(dir)
                }
            }
        }

        let canonicalRequestedPaths = Set(
            targetRelativePaths.compactMap { try? PatchPathValidator.canonicalRelativePath($0) }
        )

        var matches: [(Journal, URL)] = []
        var seenTransactions = Set<UUID>()
        for projectDirectory in projectDirectories {
            guard let directories = try? fileManager.contentsOfDirectory(
                at: projectDirectory,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else { continue }

            for directory in directories {
                let url = directory.appendingPathComponent(journalFilename)
                guard let journal = try? readJournal(url),
                      journal.status == .applied || journal.status == .prepared else { continue }
                if let targetBundleID {
                    let bundleIDs = journal.records.map(\.bundleID)
                        + (journal.createdDirectories ?? []).map(\.bundleID)
                    guard bundleIDs.contains(targetBundleID) else { continue }
                }
                let matchesProject = (projectID != nil && journal.projectID == projectID)
                let matchesPath = !canonicalRequestedPaths.isEmpty && journal.records.contains { record in
                    if let targetBundleID, record.bundleID != targetBundleID { return false }
                    let recordPath = (try? PatchPathValidator.canonicalRelativePath(record.relativePath)) ?? record.relativePath
                    return canonicalRequestedPaths.contains(recordPath)
                }
                guard matchesProject || matchesPath else { continue }
                if seenTransactions.insert(journal.transactionID).inserted {
                    matches.append((journal, url))
                }
            }
        }

        return matches
            .sorted { $0.0.createdAt > $1.0.createdAt }
            .map {
                PatchTransactionReceipt(
                    id: $0.0.transactionID,
                    projectID: $0.0.projectID,
                    journalURL: $0.1
                )
            }
    }

    @discardableResult
    static func ensureOriginalsRestored(
        bundleID: String,
        relativePaths: [String],
        backupRoot: URL,
        containerRoot: URL,
        fileManager: FileManager = .default
    ) throws -> Int {
        let root = PatchPathValidator.canonicalFileURL(containerRoot)
        let vaultDir = try originalVaultDirectory(backupRoot: backupRoot, fileManager: fileManager)
        var restoredCount = 0
        var uniquePaths: [String] = []
        var seen = Set<String>()
        for rawPath in relativePaths {
            guard let canonical = try? PatchPathValidator.canonicalRelativePath(rawPath),
                  seen.insert(canonical).inserted else { continue }
            uniquePaths.append(canonical)
        }

        for relativePath in uniquePaths {
            let key = vaultKey(bundleID: bundleID, relativePath: relativePath)
            let metaURL = vaultDir.appendingPathComponent("\(key).plist")
            let origURL = vaultDir.appendingPathComponent("\(key).original")
            guard fileManager.fileExists(atPath: metaURL.path),
                  let metaData = try? Data(contentsOf: metaURL),
                  let meta = try? PropertyListDecoder().decode(OriginalVaultMetadata.self, from: metaData),
                  let target = try? PatchPathValidator.resolveContainedTargetURL(
                    relativePath: relativePath,
                    containerRoot: root
                  ) else {
                continue
            }

            if meta.originalExisted {
                guard fileManager.fileExists(atPath: origURL.path) else { continue }
                let expectedDigest = meta.originalDigest ?? (try? digestFile(origURL))
                let currentDigest = fileManager.fileExists(atPath: target.path)
                    ? (try? digestFile(target))
                    : nil
                if currentDigest != expectedDigest || currentDigest == nil {
                    let parentDir = target.deletingLastPathComponent()
                    if !fileManager.fileExists(atPath: parentDir.path) {
                        try? fileManager.createDirectory(
                            at: parentDir,
                            withIntermediateDirectories: true
                        )
                    }
                    try atomicCopy(
                        origURL,
                        to: target,
                        fallbackPermissions: meta.posixPermissions,
                        fallbackProtection: meta.protectionType,
                        fileManager: fileManager
                    )
                    if let expectedDigest {
                        guard try digestFile(target) == expectedDigest else {
                            throw PatchPackageError.restoreFailed
                        }
                    }
                    restoredCount += 1
                }
            } else if fileManager.fileExists(atPath: target.path) {
                if let currentDigest = try? digestFile(target),
                   meta.knownReplacementDigests.isEmpty || meta.knownReplacementDigests.contains(currentDigest) {
                    try? fileManager.removeItem(at: target)
                    restoredCount += 1
                }
            }
        }
        return restoredCount
    }

    static func discardBackup(
        for receipt: PatchTransactionReceipt,
        fileManager: FileManager = .default
    ) throws {
        let journal = try readJournal(receipt.journalURL)
        guard journal.transactionID == receipt.id,
              journal.projectID == receipt.projectID,
              journal.status == .restored else {
            throw PatchPackageError.restoreFailed
        }
        let transactionDirectory = receipt.journalURL.deletingLastPathComponent().standardizedFileURL
        guard transactionDirectory.lastPathComponent == receipt.id.uuidString,
              transactionDirectory.deletingLastPathComponent().lastPathComponent == receipt.projectID.uuidString,
              transactionDirectory.path != "/" else {
            throw PatchPackageError.restoreFailed
        }
        try fileManager.removeItem(at: transactionDirectory)
    }

    static func latestReceipt(
        projectID: UUID,
        backupRoot: URL,
        targetBundleID: String? = nil,
        fileManager: FileManager = .default
    ) -> PatchTransactionReceipt? {
        let projectDirectory = backupRoot.appendingPathComponent(projectID.uuidString, isDirectory: true)
        guard let directories = try? fileManager.contentsOfDirectory(
            at: projectDirectory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else { return nil }

        return directories.compactMap { directory -> (Journal, URL)? in
            let url = directory.appendingPathComponent(journalFilename)
            guard let journal = try? readJournal(url),
                  journal.status == .applied else { return nil }
            if let targetBundleID {
                let bundleIDs = journal.records.map(\.bundleID)
                    + (journal.createdDirectories ?? []).map(\.bundleID)
                guard bundleIDs.contains(targetBundleID) else { return nil }
            }
            return (journal, url)
        }
        .sorted { $0.0.createdAt > $1.0.createdAt }
        .first
        .map {
            PatchTransactionReceipt(
                id: $0.0.transactionID,
                projectID: $0.0.projectID,
                journalURL: $0.1
            )
        }
    }

    static func requiredBundleIdentifiers(for receipt: PatchTransactionReceipt) throws -> [String] {
        let journal = try readJournal(receipt.journalURL)
        guard journal.schemaVersion == schemaVersion,
              journal.transactionID == receipt.id,
              journal.projectID == receipt.projectID else {
            throw PatchPackageError.restoreFailed
        }
        var seen = Set<String>()
        return (journal.records.map(\.bundleID)
            + (journal.createdDirectories ?? []).map(\.bundleID)).compactMap { bundleID in
                seen.insert(bundleID).inserted ? bundleID : nil
            }
    }

    private static func restoreRecords(
        _ records: [Record],
        transactionDirectory: URL,
        roots: [String: URL],
        requirePatchedDigest: Bool,
        createdDirectories: [DirectoryRecord],
        fileManager: FileManager
    ) throws {
        let backupRoot = transactionDirectory
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let vaultDir = try? originalVaultDirectory(backupRoot: backupRoot, fileManager: fileManager)

        var resolvedTargets: [(Record, URL, URL?, Data?, OriginalVaultMetadata?)] = []
        for record in records {
            guard let root = roots[record.bundleID] else {
                throw PatchPackageError.restoreFailed
            }
            let target = try PatchPathValidator.resolveContainedTargetURL(
                relativePath: record.relativePath,
                containerRoot: root
            )
            try validateFileTarget(
                target,
                relativePath: record.relativePath,
                containerRoot: root,
                allowMissingParents: true,
                fileManager: fileManager
            )

            let canonicalPath = (try? PatchPathValidator.canonicalRelativePath(record.relativePath)) ?? record.relativePath
            let key = vaultKey(bundleID: record.bundleID, relativePath: canonicalPath)
            var vaultMeta: OriginalVaultMetadata?
            var vaultOrigURL: URL?
            if let vaultDir {
                let metaURL = vaultDir.appendingPathComponent("\(key).plist")
                let candidateOrigURL = vaultDir.appendingPathComponent("\(key).original")
                if let metaData = try? Data(contentsOf: metaURL),
                   let decodedMeta = try? PropertyListDecoder().decode(OriginalVaultMetadata.self, from: metaData) {
                    vaultMeta = decodedMeta
                    if decodedMeta.originalExisted,
                       fileManager.fileExists(atPath: candidateOrigURL.path),
                       let vaultDigest = try? digestFile(candidateOrigURL),
                       vaultDigest != record.replacementDigest,
                       (decodedMeta.originalDigest == nil || vaultDigest == decodedMeta.originalDigest) {
                        vaultOrigURL = candidateOrigURL
                    }
                }
            }

            var chosenBackupURL: URL?
            var expectedOriginalDigest: Data?

            if let vaultOrigURL {
                chosenBackupURL = vaultOrigURL
                expectedOriginalDigest = vaultMeta?.originalDigest ?? (try? digestFile(vaultOrigURL))
            } else if record.originalExisted, let backupFilename = record.backupFilename {
                let txBackup = transactionDirectory.appendingPathComponent(backupFilename)
                if fileManager.fileExists(atPath: txBackup.path),
                   let txDigest = try? digestFile(txBackup) {
                    if let expected = record.originalDigest, txDigest == expected {
                        chosenBackupURL = txBackup
                        expectedOriginalDigest = expected
                    } else if record.originalDigest == nil {
                        chosenBackupURL = txBackup
                        expectedOriginalDigest = txDigest
                    }
                    // Seed OriginalVault from legacy authentic transaction backup if needed
                    if let vaultDir,
                       txDigest != record.replacementDigest,
                       vaultOrigURL == nil {
                        let seedOrigURL = vaultDir.appendingPathComponent("\(key).original")
                        let seedMetaURL = vaultDir.appendingPathComponent("\(key).plist")
                        if !fileManager.fileExists(atPath: seedOrigURL.path) {
                            try? fileManager.copyItem(at: txBackup, to: seedOrigURL)
                            try? fileManager.setAttributes(
                                [.protectionKey: FileProtectionType.complete],
                                ofItemAtPath: seedOrigURL.path
                            )
                            let seededMeta = OriginalVaultMetadata(
                                bundleID: record.bundleID,
                                relativePath: canonicalPath,
                                originalExisted: true,
                                originalDigest: txDigest,
                                posixPermissions: 0o644,
                                protectionType: FileProtectionType.completeUntilFirstUserAuthentication.rawValue,
                                knownReplacementDigests: [record.replacementDigest]
                            )
                            if let encoded = try? PropertyListEncoder().encode(seededMeta) {
                                try? encoded.write(to: seedMetaURL, options: .atomic)
                            }
                        }
                    }
                }
            }

            let shouldRestoreOriginalFile = (vaultMeta?.originalExisted ?? record.originalExisted)
            if shouldRestoreOriginalFile, chosenBackupURL == nil {
                throw PatchPackageError.restoreFailed
            }
            resolvedTargets.append((record, target, chosenBackupURL, expectedOriginalDigest, vaultMeta))
        }

        for (record, target, chosenBackupURL, expectedOriginalDigest, vaultMeta) in resolvedTargets.reversed() {
            let shouldRestoreOriginalFile = (vaultMeta?.originalExisted ?? record.originalExisted)
            if shouldRestoreOriginalFile, let backup = chosenBackupURL {
                let parentDir = target.deletingLastPathComponent()
                if !fileManager.fileExists(atPath: parentDir.path) {
                    try fileManager.createDirectory(at: parentDir, withIntermediateDirectories: true)
                }
                try atomicCopy(
                    backup,
                    to: target,
                    fallbackPermissions: vaultMeta?.posixPermissions,
                    fallbackProtection: vaultMeta?.protectionType,
                    fileManager: fileManager
                )
                if let expectedOriginalDigest {
                    guard try digestFile(target) == expectedOriginalDigest else {
                        throw PatchPackageError.restoreFailed
                    }
                }
            } else if fileManager.fileExists(atPath: target.path) {
                try fileManager.removeItem(at: target)
            }
        }

        for directory in createdDirectories.reversed() {
            guard let root = roots[directory.bundleID] else {
                continue
            }
            let target = try PatchPathValidator.resolveContainedTargetURL(
                relativePath: directory.relativePath,
                containerRoot: root
            )
            guard fileManager.fileExists(atPath: target.path) else { continue }
            let values = try target.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard values.isSymbolicLink != true, values.isDirectory == true else {
                continue
            }
            let contents = (try? fileManager.contentsOfDirectory(atPath: target.path)) ?? []
            if contents.isEmpty {
                try? fileManager.removeItem(at: target)
            }
        }
    }

    private static func validateFileTarget(
        _ target: URL,
        relativePath: String,
        containerRoot: URL,
        allowMissingParents: Bool,
        fileManager: FileManager
    ) throws {
        let components = try PatchPathValidator.canonicalRelativePath(relativePath)
            .split(separator: "/")
            .map(String.init)
        var cursor = PatchPathValidator.canonicalFileURL(containerRoot)
        for component in components.dropLast() {
            cursor.appendPathComponent(component, isDirectory: true)
            guard fileManager.fileExists(atPath: cursor.path) else {
                if allowMissingParents { break }
                throw PatchPackageError.applyFailed
            }
            let values = try cursor.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard values.isSymbolicLink != true else {
                throw PatchPackageError.symbolicLinkUnsupported
            }
            guard values.isDirectory == true else {
                throw PatchPackageError.applyFailed
            }
        }
        if fileManager.fileExists(atPath: target.path) {
            let values = try target.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard values.isSymbolicLink != true else {
                throw PatchPackageError.symbolicLinkUnsupported
            }
            guard values.isDirectory != true else {
                throw PatchPackageError.applyFailed
            }
        }
    }

    private static func validateDirectoryTarget(
        _ target: URL,
        relativePath: String,
        containerRoot: URL,
        fileManager: FileManager
    ) throws {
        let components = try PatchPathValidator.canonicalRelativePath(relativePath)
            .split(separator: "/").map(String.init)
        var cursor = PatchPathValidator.canonicalFileURL(containerRoot)
        for component in components {
            cursor.appendPathComponent(component, isDirectory: true)
            guard fileManager.fileExists(atPath: cursor.path) else { break }
            let values = try cursor.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard values.isSymbolicLink != true else {
                throw PatchPackageError.symbolicLinkUnsupported
            }
            guard values.isDirectory == true else {
                throw PatchPackageError.applyFailed
            }
        }
        if fileManager.fileExists(atPath: target.path) {
            let values = try target.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard values.isSymbolicLink != true, values.isDirectory == true else {
                throw PatchPackageError.applyFailed
            }
        }
    }

    private static func directoryKeySort(_ lhs: String, _ rhs: String) -> Bool {
        let leftDepth = lhs.filter { $0 == "/" }.count
        let rightDepth = rhs.filter { $0 == "/" }.count
        return leftDepth == rightDepth ? lhs < rhs : leftDepth < rightDepth
    }

    private static func atomicWrite(
        _ data: Data,
        to target: URL,
        preservingExistingAttributes: Bool,
        fileManager: FileManager
    ) throws {
        let staging = target.deletingLastPathComponent()
            .appendingPathComponent(".3105-patch-\(UUID().uuidString)")
        var attributes: [FileAttributeKey: Any] = [:]
        if preservingExistingAttributes,
           let current = try? fileManager.attributesOfItem(atPath: target.path) {
            if let permissions = current[.posixPermissions] { attributes[.posixPermissions] = permissions }
            if let protection = current[.protectionKey] { attributes[.protectionKey] = protection }
        }
        guard fileManager.createFile(atPath: staging.path, contents: data, attributes: attributes) else {
            throw PatchPackageError.applyFailed
        }
        defer { try? fileManager.removeItem(at: staging) }
        let handle = try FileHandle(forWritingTo: staging)
        try handle.synchronize()
        try handle.close()
        guard rename(staging.path, target.path) == 0 else {
            throw PatchPackageError.applyFailed
        }
    }

    private static func atomicCopy(
        _ source: URL,
        to target: URL,
        fallbackPermissions: Int? = nil,
        fallbackProtection: String? = nil,
        fileManager: FileManager
    ) throws {
        let staging = target.deletingLastPathComponent()
            .appendingPathComponent(".3105-restore-\(UUID().uuidString)")
        defer { try? fileManager.removeItem(at: staging) }
        var preservedAttributes: [FileAttributeKey: Any] = [:]
        if let current = try? fileManager.attributesOfItem(atPath: target.path) {
            if let permissions = current[.posixPermissions] {
                preservedAttributes[.posixPermissions] = permissions
            }
            if let protection = current[.protectionKey] {
                preservedAttributes[.protectionKey] = protection
            }
        }
        if preservedAttributes[.posixPermissions] == nil {
            preservedAttributes[.posixPermissions] = NSNumber(value: fallbackPermissions ?? 0o644)
        }
        if preservedAttributes[.protectionKey] == nil {
            let rawProtection = fallbackProtection ?? FileProtectionType.completeUntilFirstUserAuthentication.rawValue
            preservedAttributes[.protectionKey] = FileProtectionType(rawValue: rawProtection)
        }
        try fileManager.copyItem(at: source, to: staging)
        try? fileManager.setAttributes(preservedAttributes, ofItemAtPath: staging.path)
        let handle = try FileHandle(forWritingTo: staging)
        try handle.synchronize()
        try handle.close()
        if rename(staging.path, target.path) != 0 {
            if fileManager.fileExists(atPath: target.path) {
                try? fileManager.removeItem(at: target)
            }
            guard rename(staging.path, target.path) == 0 else {
                throw PatchPackageError.restoreFailed
            }
        }
        try? fileManager.setAttributes(preservedAttributes, ofItemAtPath: target.path)
    }

    private static func originalVaultDirectory(
        backupRoot: URL,
        fileManager: FileManager
    ) throws -> URL {
        let vaultDir = backupRoot.appendingPathComponent(originalVaultDirectoryName, isDirectory: true)
        if !fileManager.fileExists(atPath: vaultDir.path) {
            try fileManager.createDirectory(
                at: vaultDir,
                withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.complete]
            )
        }
        return vaultDir
    }

    private static func vaultKey(bundleID: String, relativePath: String) -> String {
        let canonical = (try? PatchPathValidator.canonicalRelativePath(relativePath)) ?? relativePath
        let raw = Data("\(bundleID.lowercased())::\(canonical)".utf8)
        return SHA256.hash(data: raw).map { String(format: "%02x", $0) }.joined()
    }

    private static func captureOriginalInVaultIfNeeded(
        bundleID: String,
        relativePath: String,
        targetURL: URL,
        replacementDigest: Data,
        backupRoot: URL,
        fileManager: FileManager
    ) throws -> (originalExisted: Bool, originalFileURL: URL?, originalDigest: Data?) {
        let canonicalPath = try PatchPathValidator.canonicalRelativePath(relativePath)
        let vaultDir = try originalVaultDirectory(backupRoot: backupRoot, fileManager: fileManager)
        let key = vaultKey(bundleID: bundleID, relativePath: canonicalPath)
        let metaURL = vaultDir.appendingPathComponent("\(key).plist")
        let origURL = vaultDir.appendingPathComponent("\(key).original")

        let existingMeta: OriginalVaultMetadata? = {
            guard fileManager.fileExists(atPath: metaURL.path),
                  let data = try? Data(contentsOf: metaURL) else { return nil }
            return try? PropertyListDecoder().decode(OriginalVaultMetadata.self, from: data)
        }()

        let targetExists = fileManager.fileExists(atPath: targetURL.path)
        let diskDigest = targetExists ? (try? digestFile(targetURL)) : nil

        let activeReceiptsForPath = allActiveReceipts(
            projectID: nil,
            backupRoot: backupRoot,
            targetBundleID: bundleID,
            targetRelativePaths: [canonicalPath],
            fileManager: fileManager
        )

        let diskMatchesKnownReplacement: Bool = {
            guard let diskDigest else { return false }
            if diskDigest == replacementDigest { return true }
            if existingMeta?.knownReplacementDigests.contains(diskDigest) == true { return true }
            for receipt in activeReceiptsForPath {
                if let journal = try? readJournal(receipt.journalURL),
                   journal.records.contains(where: { $0.replacementDigest == diskDigest }) {
                    return true
                }
            }
            return false
        }()

        // Check if OriginalVault already holds a verified pristine original backup
        if var meta = existingMeta {
            let hasValidVaultFile: Bool = {
                if !meta.originalExisted { return true }
                guard fileManager.fileExists(atPath: origURL.path),
                      let vaultDigest = try? digestFile(origURL) else { return false }
                if let expected = meta.originalDigest {
                    return vaultDigest == expected && !meta.knownReplacementDigests.contains(vaultDigest)
                }
                return !meta.knownReplacementDigests.contains(vaultDigest)
            }()

            if hasValidVaultFile {
                // Only refresh the golden original if NO patch is currently active for this path
                // AND the file on disk is a genuine new game file (not any known replacement payload).
                if activeReceiptsForPath.isEmpty && !diskMatchesKnownReplacement {
                    if targetExists, let diskDigest, diskDigest != meta.originalDigest {
                        let staging = vaultDir.appendingPathComponent(".vault-\(UUID().uuidString)")
                        defer { try? fileManager.removeItem(at: staging) }
                        try fileManager.copyItem(at: targetURL, to: staging)
                        let handle = try FileHandle(forWritingTo: staging)
                        try handle.synchronize()
                        try handle.close()
                        if fileManager.fileExists(atPath: origURL.path) {
                            try? fileManager.removeItem(at: origURL)
                        }
                        _ = rename(staging.path, origURL.path)
                        try? fileManager.setAttributes(
                            [.protectionKey: FileProtectionType.complete],
                            ofItemAtPath: origURL.path
                        )
                        let attrs = try? fileManager.attributesOfItem(atPath: targetURL.path)
                        meta.originalExisted = true
                        meta.originalDigest = diskDigest
                        meta.posixPermissions = (attrs?[.posixPermissions] as? NSNumber)?.intValue ?? meta.posixPermissions ?? 0o644
                        meta.protectionType = (attrs?[.protectionKey] as? FileProtectionType)?.rawValue ?? meta.protectionType
                    }
                }
                if !meta.knownReplacementDigests.contains(replacementDigest) {
                    meta.knownReplacementDigests.append(replacementDigest)
                }
                let encoder = PropertyListEncoder()
                encoder.outputFormat = .binary
                try? encoder.encode(meta).write(to: metaURL, options: .atomic)
                return (meta.originalExisted, meta.originalExisted ? origURL : nil, meta.originalDigest)
            }
        }

        // No valid golden original in OriginalVault yet.
        // First check if an active transaction already captured the true original before the disk was patched.
        if diskMatchesKnownReplacement {
            for receipt in activeReceiptsForPath.reversed() {
                guard let journal = try? readJournal(receipt.journalURL) else { continue }
                let txDir = receipt.journalURL.deletingLastPathComponent()
                for record in journal.records where record.bundleID == bundleID {
                    let recPath = (try? PatchPathValidator.canonicalRelativePath(record.relativePath)) ?? record.relativePath
                    guard recPath == canonicalPath else { continue }
                    if record.originalExisted,
                       let backupFilename = record.backupFilename {
                        let txBackup = txDir.appendingPathComponent(backupFilename)
                        if fileManager.fileExists(atPath: txBackup.path),
                           let txDigest = try? digestFile(txBackup),
                           txDigest != replacementDigest,
                           txDigest != record.replacementDigest {
                            if fileManager.fileExists(atPath: origURL.path) {
                                try? fileManager.removeItem(at: origURL)
                            }
                            try fileManager.copyItem(at: txBackup, to: origURL)
                            try? fileManager.setAttributes(
                                [.protectionKey: FileProtectionType.complete],
                                ofItemAtPath: origURL.path
                            )
                            let meta = OriginalVaultMetadata(
                                bundleID: bundleID,
                                relativePath: canonicalPath,
                                originalExisted: true,
                                originalDigest: txDigest,
                                posixPermissions: 0o644,
                                protectionType: FileProtectionType.completeUntilFirstUserAuthentication.rawValue,
                                knownReplacementDigests: Array(Set([replacementDigest, record.replacementDigest]))
                            )
                            let encoder = PropertyListEncoder()
                            encoder.outputFormat = .binary
                            try encoder.encode(meta).write(to: metaURL, options: .atomic)
                            return (true, origURL, txDigest)
                        }
                    }
                }
            }
        }

        if targetExists, let diskDigest {
            let staging = vaultDir.appendingPathComponent(".vault-\(UUID().uuidString)")
            defer { try? fileManager.removeItem(at: staging) }
            try fileManager.copyItem(at: targetURL, to: staging)
            let handle = try FileHandle(forWritingTo: staging)
            try handle.synchronize()
            try handle.close()
            if fileManager.fileExists(atPath: origURL.path) {
                try? fileManager.removeItem(at: origURL)
            }
            guard rename(staging.path, origURL.path) == 0 else {
                throw PatchPackageError.applyFailed
            }
            try? fileManager.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: origURL.path
            )
            let attrs = try? fileManager.attributesOfItem(atPath: targetURL.path)
            let permissions = (attrs?[.posixPermissions] as? NSNumber)?.intValue ?? 0o644
            let protection = (attrs?[.protectionKey] as? FileProtectionType)?.rawValue
                ?? FileProtectionType.completeUntilFirstUserAuthentication.rawValue
            let meta = OriginalVaultMetadata(
                bundleID: bundleID,
                relativePath: canonicalPath,
                originalExisted: true,
                originalDigest: diskDigest,
                posixPermissions: permissions,
                protectionType: protection,
                knownReplacementDigests: [replacementDigest]
            )
            let encoder = PropertyListEncoder()
            encoder.outputFormat = .binary
            try encoder.encode(meta).write(to: metaURL, options: .atomic)
            return (true, origURL, diskDigest)
        } else {
            let meta = OriginalVaultMetadata(
                bundleID: bundleID,
                relativePath: canonicalPath,
                originalExisted: false,
                originalDigest: nil,
                posixPermissions: nil,
                protectionType: nil,
                knownReplacementDigests: [replacementDigest]
            )
            let encoder = PropertyListEncoder()
            encoder.outputFormat = .binary
            try encoder.encode(meta).write(to: metaURL, options: .atomic)
            return (false, nil, nil)
        }
    }

    private static func writeJournal(_ journal: Journal, to url: URL) throws {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        try encoder.encode(journal).write(to: url, options: .atomic)
    }

    private static func readJournal(_ url: URL) throws -> Journal {
        try PropertyListDecoder().decode(Journal.self, from: Data(contentsOf: url))
    }

    private static func digest(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    private static func digestFile(_ url: URL) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try handle.read(upToCount: 1_024 * 1_024), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return Data(hasher.finalize())
    }

    private static func containerFingerprint(_ url: URL) -> Data {
        digest(Data(PatchPathValidator.canonicalFileURL(url).path.utf8))
    }
}
