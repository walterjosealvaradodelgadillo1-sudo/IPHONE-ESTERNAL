// ThreeOneOSFive/helpers/LicenseManager.swift
import Combine
import CoreFoundation
import CryptoKit
import Foundation
import MachO
import Security
import UIKit

enum KeyAuthMode: String, CaseIterable, Identifiable {
    case license = "LICENSE"
    case login = "LOGIN"
    case register = "REGISTER"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .license: return "LICENSE KEY"
        case .login: return "ACCOUNT"
        case .register: return "REGISTER"
        }
    }

    var icon: String {
        switch self {
        case .license: return "key.horizontal.fill"
        case .login: return "person.badge.key.fill"
        case .register: return "person.crop.circle.badge.plus"
        }
    }
}

enum KeyAuthStatusLevel: Equatable {
    case neutral
    case verifying
    case success
    case warning
    case error
}

struct KeyAuthConfiguration {
    static let appName = "EXTERNAL IPHONE"
    static let ownerID = "S12mtcUb8r"
    static let appSecret = "faf96321eed09a7d9986b033624d63c5956c8eef5d3f323cb7e5beaa7f06e273"
    static let appVersion = "1.0"
    static let primaryEndpoint = "https://keyauth.win/api/1.2/"
    static let backupEndpoint = "https://keyauth.cc/api/1.2/"
}

@MainActor
final class LicenseManager: ObservableObject {
    @Published private(set) var expirationDate: Date?
    @Published private(set) var hasExpiryInformation = false
    @Published private(set) var expiryDateWasProvided = false
    @Published private(set) var lastCheckAttemptAt: Date?
    @Published private(set) var isActive = false
    @Published private(set) var isBusy = false
    @Published private(set) var isLoadingScreen = true
    @Published private(set) var clientSessionRevision = 0
    @Published private(set) var message: String?
    @Published private(set) var contactOwner: String?

    // Extended KeyAuth professional telemetry & profile metadata
    @Published var authMode: KeyAuthMode = .license
    @Published private(set) var statusLevel: KeyAuthStatusLevel = .neutral
    @Published private(set) var subscriptionName: String = "EXTERNAL VIP"
    @Published private(set) var authenticatedUsername: String?
    @Published private(set) var clientIPAddress: String?
    @Published private(set) var createdAtDate: Date?
    @Published private(set) var lastLoginDate: Date?
    @Published private(set) var keyAuthSessionID: String?
    @Published private(set) var serverOnline = false
    @Published private(set) var totalUsersCount: String?
    @Published private(set) var onlineUsersCount: String?
    @Published private(set) var activeHwidHash: String = ""

    private let service = "com.m3sb.external-ios.activation"
    private let keyAccount = "license-key"
    private let usernameAccount = "keyauth-username"
    private let passwordAccount = "keyauth-password"
    private let authModeAccount = "keyauth-mode"
    private let subscriptionAccount = "keyauth-subscription"
    private let clientSessionAccount = "vesperdash-client-session"
    private let expirationAccount = "license-expiration"
    private let expiryKnownAccount = "license-expiry-known"
    private let expiryPresentAccount = "license-expiry-present"
    private let lastCheckAccount = "license-last-check-expiry-v2"
    private let deviceService = "com.m3sb.api.instance.v1"
    private let deviceAccount = "default"

    private var lastAttemptAt: Date?
    private var silentCheckWorkItem: DispatchWorkItem?
    private var silentCheckID: UUID?
    private var activeVerificationID: UUID?

    init() {
        let savedKey = string(for: keyAccount)
        let savedUser = string(for: usernameAccount)
        isActive = (savedKey != nil) || (savedUser != nil && string(for: passwordAccount) != nil)
        hasExpiryInformation = string(for: expiryKnownAccount) == "true"
        expiryDateWasProvided = string(for: expiryPresentAccount) == "true"
        if let savedMode = string(for: authModeAccount), let mode = KeyAuthMode(rawValue: savedMode) {
            authMode = mode
        }
        if let savedSub = string(for: subscriptionAccount), !savedSub.isEmpty {
            subscriptionName = savedSub
        }
        authenticatedUsername = savedUser ?? savedKey
        if let value = string(for: expirationAccount), let timestamp = Double(value) {
            expirationDate = Date(timeIntervalSince1970: timestamp)
        }
        if let value = string(for: lastCheckAccount), let timestamp = Double(value) {
            lastCheckAttemptAt = Date(timeIntervalSince1970: timestamp)
        }
        if string(for: clientSessionAccount) != nil {
            clientSessionRevision = 1
        }
        isLoadingScreen = false
        activeHwidHash = hwid()
    }

    var hasRememberedKey: Bool {
        string(for: keyAccount) != nil || (string(for: usernameAccount) != nil && string(for: passwordAccount) != nil)
    }

    func clientSessionToken() -> String? {
        if let token = string(for: clientSessionAccount), !token.isEmpty {
            return token
        }
        return keyAuthSessionID
    }

    func rememberedKey() -> String? {
        if let key = string(for: keyAccount), !key.isEmpty {
            return key
        }
        return string(for: usernameAccount)
    }

    func rememberedUsername() -> String? {
        string(for: usernameAccount)
    }

    func rememberedPassword() -> String? {
        string(for: passwordAccount)
    }

    func hwid() -> String {
        let rawDevice = deviceIdentifier()
        return sha256("KEYAUTH-IOS-\(rawDevice)").prefix(36).uppercased()
    }

    func pingServerHandshake() {
        guard !isBusy else { return }
        Task {
            do {
                let initResponse = try await performKeyAuthInit()
                self.keyAuthSessionID = initResponse.sessionID
                self.serverOnline = true
                self.totalUsersCount = initResponse.numUsers
                self.onlineUsersCount = initResponse.numOnlineUsers
            } catch {
                self.serverOnline = false
            }
        }
    }

    func beginLaunchSession() {
        guard !isBusy else { return }
        guard hasRememberedKey else {
            isActive = false
            isLoadingScreen = false
            statusLevel = .neutral
            message = "Authentication required — enter your KeyAuth license or account"
            pingServerHandshake()
            return
        }
        isActive = true
        isLoadingScreen = false
        guard silentCheckID == nil else { return }
        let checkID = UUID()
        silentCheckID = checkID
        let workItem = DispatchWorkItem { [weak self] in
            guard let self, self.silentCheckID == checkID else { return }
            self.silentCheckID = nil
            self.silentCheckWorkItem = nil
            guard !self.isBusy else { return }
            self.recordCheckAttempt()
            self.isBusy = true
            let verificationID = UUID()
            self.activeVerificationID = verificationID
            if let savedUser = self.string(for: self.usernameAccount),
               let savedPass = self.string(for: self.passwordAccount),
               !savedUser.isEmpty, !savedPass.isEmpty,
               self.string(for: self.authModeAccount) == KeyAuthMode.login.rawValue {
                self.verifyKeyAuth(payload: .login(username: savedUser, password: savedPass), silent: true, verificationID: verificationID)
            } else if let key = self.string(for: self.keyAccount), !key.isEmpty {
                self.verifyKeyAuth(payload: .license(key: key), silent: true, verificationID: verificationID)
            } else {
                self.isBusy = false
            }
        }
        silentCheckWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + 4, execute: workItem)
    }

    func cancelPendingSilentCheck() {
        silentCheckID = nil
        silentCheckWorkItem?.cancel()
        silentCheckWorkItem = nil
    }

    func activate(key: String) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !isBusy else { return }
        guard throttleCheck() else { return }
        authMode = .license
        startVerificationUI(statusText: "Authenticating license with KeyAuth Cloud…")
        let verificationID = UUID()
        activeVerificationID = verificationID
        verifyKeyAuth(payload: .license(key: trimmed), silent: false, verificationID: verificationID)
    }

    func login(username: String, password: String) {
        let cleanUser = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanPass = password.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanUser.isEmpty, !cleanPass.isEmpty, !isBusy else { return }
        guard throttleCheck() else { return }
        authMode = .login
        startVerificationUI(statusText: "Signing in to KeyAuth account…")
        let verificationID = UUID()
        activeVerificationID = verificationID
        verifyKeyAuth(payload: .login(username: cleanUser, password: cleanPass), silent: false, verificationID: verificationID)
    }

    func register(username: String, password: String, key: String) {
        let cleanUser = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanPass = password.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanUser.isEmpty, !cleanPass.isEmpty, !cleanKey.isEmpty, !isBusy else { return }
        guard throttleCheck() else { return }
        authMode = .register
        startVerificationUI(statusText: "Registering account & binding HWID…")
        let verificationID = UUID()
        activeVerificationID = verificationID
        verifyKeyAuth(payload: .register(username: cleanUser, password: cleanPass, key: cleanKey), silent: false, verificationID: verificationID)
    }

    func refresh() {
        beginLaunchSession()
    }

    func deactivate() {
        cancelPendingSilentCheck()
        activeVerificationID = nil
        isBusy = false
        revokeClientSession()
        delete(keyAccount)
        delete(usernameAccount)
        delete(passwordAccount)
        delete(authModeAccount)
        delete(subscriptionAccount)
        delete(clientSessionAccount)
        delete(expirationAccount)
        delete(expiryKnownAccount)
        delete(expiryPresentAccount)
        delete(lastCheckAccount)
        expirationDate = nil
        hasExpiryInformation = false
        expiryDateWasProvided = false
        lastCheckAttemptAt = nil
        authenticatedUsername = nil
        clientIPAddress = nil
        keyAuthSessionID = nil
        isActive = false
        isLoadingScreen = false
        statusLevel = .neutral
        message = "Session closed & license unbound from local keychain"
    }

    private func throttleCheck() -> Bool {
        cancelPendingSilentCheck()
        if let lastAttemptAt, Date().timeIntervalSince(lastAttemptAt) < 1.0 {
            statusLevel = .warning
            message = "Please wait a moment before trying again"
            return false
        }
        lastAttemptAt = Date()
        return true
    }

    private func startVerificationUI(statusText: String) {
        isBusy = true
        isLoadingScreen = true
        statusLevel = .verifying
        message = statusText
        recordCheckAttempt()
    }

    private func recordCheckAttempt() {
        let now = Date()
        lastCheckAttemptAt = now
        save(String(now.timeIntervalSince1970), for: lastCheckAccount)
    }

    // MARK: - KeyAuth 1.2 Protocol Engine

    private enum KeyAuthPayload {
        case license(key: String)
        case login(username: String, password: String)
        case register(username: String, password: String, key: String)

        var credentialKeyForStorage: String {
            switch self {
            case .license(let key): return key
            case .login(let username, _): return username
            case .register(_, _, let key): return key
            }
        }
    }

    private struct KeyAuthInitResult {
        let sessionID: String
        let numUsers: String?
        let numOnlineUsers: String?
        let numKeys: String?
        let appVersion: String?
    }

    private struct KeyAuthVerifiedState {
        let valid: Bool
        let message: String
        let sessionID: String
        let username: String
        let subscription: String
        let expiresAt: Date?
        let hasExpiryField: Bool
        let ipAddress: String?
        let hwid: String?
        let createdAt: Date?
        let lastLogin: Date?
        let rawInfo: [String: Any]
    }

    private func verifyKeyAuth(payload: KeyAuthPayload, silent: Bool, verificationID: UUID) {
        Task {
            do {
                let initResult = try await performKeyAuthInit()
                self.keyAuthSessionID = initResult.sessionID
                self.serverOnline = true
                self.totalUsersCount = initResult.numUsers
                self.onlineUsersCount = initResult.numOnlineUsers

                let verifiedState = try await performKeyAuthAuthenticate(
                    payload: payload,
                    sessionID: initResult.sessionID
                )

                guard self.activeVerificationID == verificationID else { return }

                // Bridge with VesperDash if available; otherwise use KeyAuth session token directly.
                let bridgedSessionToken = await self.tryBridgeWithVesperDash(
                    verifiedState: verifiedState,
                    key: payload.credentialKeyForStorage,
                    deviceID: self.deviceIdentifier()
                ) ?? verifiedState.sessionID

                self.completeKeyAuthVerification(
                    state: verifiedState,
                    payload: payload,
                    sessionToken: bridgedSessionToken,
                    silent: silent,
                    verificationID: verificationID
                )
            } catch let error as APIError {
                guard self.activeVerificationID == verificationID else { return }
                self.handleVerificationFailure(error, silent: silent, verificationID: verificationID)
            } catch {
                guard self.activeVerificationID == verificationID else { return }
                self.handleVerificationFailure(
                    .message("KeyAuth network error: \(error.localizedDescription)"),
                    silent: silent,
                    verificationID: verificationID
                )
            }
        }
    }

    private func performKeyAuthInit() async throws -> KeyAuthInitResult {
        let initParams: [String: String] = [
            "type": "init",
            "ver": KeyAuthConfiguration.appVersion,
            "name": KeyAuthConfiguration.appName,
            "ownerid": KeyAuthConfiguration.ownerID
        ]

        let json = try await postKeyAuthForm(params: initParams)
        let success = (json["success"] as? Bool) ?? false
        let serverMessage = (json["message"] as? String) ?? "KeyAuth initialization failed"

        if !success {
            if serverMessage.lowercased().contains("outdated") || serverMessage.lowercased().contains("version") {
                throw APIError.revoked(serverMessage)
            }
            throw APIError.message("KeyAuth Init: \(serverMessage)")
        }

        guard let sessionID = json["sessionid"] as? String, !sessionID.isEmpty else {
            throw APIError.message("KeyAuth did not return a valid session ID")
        }

        let appInfo = json["appinfo"] as? [String: Any]
        return KeyAuthInitResult(
            sessionID: sessionID,
            numUsers: appInfo?["numUsers"] as? String,
            numOnlineUsers: appInfo?["numOnlineUsers"] as? String,
            numKeys: appInfo?["numKeys"] as? String,
            appVersion: appInfo?["version"] as? String
        )
    }

    private func performKeyAuthAuthenticate(payload: KeyAuthPayload, sessionID: String) async throws -> KeyAuthVerifiedState {
        let deviceHwid = hwid()
        var params: [String: String] = [
            "sessionid": sessionID,
            "name": KeyAuthConfiguration.appName,
            "ownerid": KeyAuthConfiguration.ownerID,
            "hwid": deviceHwid
        ]

        switch payload {
        case .license(let key):
            params["type"] = "license"
            params["key"] = key
        case .login(let username, let password):
            params["type"] = "login"
            params["username"] = username
            params["pass"] = password
        case .register(let username, let password, let key):
            params["type"] = "register"
            params["username"] = username
            params["pass"] = password
            params["key"] = key
        }

        let json = try await postKeyAuthForm(params: params)
        let success = (json["success"] as? Bool) ?? false
        let serverMessage = (json["message"] as? String) ?? "Authentication rejected by KeyAuth"

        guard success else {
            let lower = serverMessage.lowercased()
            let fatalRevokeKeywords = [
                "invalid", "expired", "banned", "blacklisted", "hwid",
                "doesn't exist", "does not exist", "not found", "used",
                "taken", "password", "subscription"
            ]
            if fatalRevokeKeywords.contains(where: { lower.contains($0) }) {
                throw APIError.revoked(Self.humanizeKeyAuthMessage(serverMessage))
            }
            throw APIError.message(Self.humanizeKeyAuthMessage(serverMessage))
        }

        let info = (json["info"] as? [String: Any]) ?? [:]
        let username = (info["username"] as? String) ?? payload.credentialKeyForStorage
        let ip = info["ip"] as? String
        let returnedHwid = (info["hwid"] as? String) ?? deviceHwid
        let createdDate = Self.parseUnixTimestamp(info["createdate"])
        let lastLoginDate = Self.parseUnixTimestamp(info["lastlogin"])

        var subscriptionTitle = "EXTERNAL VIP"
        var parsedExpiry: Date?
        var hasExpiry = false

        if let subscriptions = info["subscriptions"] as? [[String: Any]],
           let primarySub = subscriptions.first {
            if let subName = primarySub["subscription"] as? String, !subName.isEmpty {
                subscriptionTitle = subName.uppercased()
            }
            if let rawExpiry = primarySub["expiry"] {
                hasExpiry = true
                parsedExpiry = Self.parseUnixTimestamp(rawExpiry)
            }
        }

        return KeyAuthVerifiedState(
            valid: true,
            message: Self.humanizeKeyAuthMessage(serverMessage),
            sessionID: sessionID,
            username: username,
            subscription: subscriptionTitle,
            expiresAt: parsedExpiry,
            hasExpiryField: hasExpiry,
            ipAddress: ip,
            hwid: returnedHwid,
            createdAt: createdDate,
            lastLogin: lastLoginDate,
            rawInfo: info
        )
    }

    private func postKeyAuthForm(params: [String: String]) async throws -> [String: Any] {
        let endpoints = [KeyAuthConfiguration.primaryEndpoint, KeyAuthConfiguration.backupEndpoint]
        var lastError: Error?

        for endpoint in endpoints {
            guard let url = URL(string: endpoint) else { continue }
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.timeoutInterval = 15
            request.cachePolicy = .reloadIgnoringLocalCacheData
            request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
            request.setValue("KeyAuth-iOS-SDK/1.2 (EXTERNAL IPHONE; iOS \(UIDevice.current.systemVersion))", forHTTPHeaderField: "User-Agent")

            let formBody = params
                .sorted { $0.key < $1.key }
                .map { key, value in
                    "\(Self.urlFormEncode(key))=\(Self.urlFormEncode(value))"
                }
                .joined(separator: "&")
            request.httpBody = Data(formBody.utf8)

            do {
                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse else {
                    throw APIError.message("Invalid response from KeyAuth gateway")
                }
                guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    throw APIError.message("KeyAuth gateway returned non-JSON (HTTP \(http.statusCode))")
                }
                return json
            } catch {
                lastError = error
            }
        }

        throw lastError ?? APIError.message("Unable to reach KeyAuth servers")
    }

    private func tryBridgeWithVesperDash(verifiedState: KeyAuthVerifiedState, key: String, deviceID: String) async -> String? {
        guard let url = URL(string: VesperStringVault.vesperDashClientSessionURL + "/bridge") else {
            return nil
        }
        var providerResult: [String: Any] = [
            "valid": true,
            "status": "active",
            "license": key,
            "provider": "keyauth",
            "app_name": KeyAuthConfiguration.appName,
            "owner_id": KeyAuthConfiguration.ownerID,
            "session_id": verifiedState.sessionID,
            "subscription": verifiedState.subscription,
            "username": verifiedState.username
        ]
        if let expiry = verifiedState.expiresAt {
            providerResult["expires_at"] = Int(expiry.timeIntervalSince1970)
        }
        let body: [String: Any] = [
            "key": key,
            "device_id": deviceID,
            "provider": "keyauth",
            "keyauth_session_id": verifiedState.sessionID,
            "provider_result": providerResult
        ]
        guard let bodyData = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]) else {
            return nil
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = bodyData
        request.timeoutInterval = 6
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let token = json["client_session"] as? String, !token.isEmpty else {
                return nil
            }
            return token
        } catch {
            return nil
        }
    }

    private func completeKeyAuthVerification(
        state: KeyAuthVerifiedState,
        payload: KeyAuthPayload,
        sessionToken: String,
        silent: Bool,
        verificationID: UUID
    ) {
        guard activeVerificationID == verificationID else { return }
        activeVerificationID = nil
        isBusy = false
        if !silent { isLoadingScreen = false }

        let hasNotExpired = state.expiresAt.map { $0 > Date() } ?? true
        guard state.valid, hasNotExpired else {
            handleVerificationFailure(.revoked("Your KeyAuth subscription has expired"), silent: silent, verificationID: verificationID)
            return
        }

        expirationDate = state.expiresAt
        hasExpiryInformation = true
        save("true", for: expiryKnownAccount)
        expiryDateWasProvided = state.hasExpiryField
        save(state.hasExpiryField ? "true" : "false", for: expiryPresentAccount)

        if let expirationDate = state.expiresAt {
            save(String(expirationDate.timeIntervalSince1970), for: expirationAccount)
        } else {
            delete(expirationAccount)
        }

        subscriptionName = state.subscription
        save(state.subscription, for: subscriptionAccount)
        authenticatedUsername = state.username
        clientIPAddress = state.ipAddress
        createdAtDate = state.createdAt
        lastLoginDate = state.lastLogin
        if let hwid = state.hwid, !hwid.isEmpty {
            activeHwidHash = hwid
        }

        switch payload {
        case .license(let key):
            save(key, for: keyAccount)
            save(KeyAuthMode.license.rawValue, for: authModeAccount)
        case .login(let username, let password):
            save(username, for: usernameAccount)
            save(password, for: passwordAccount)
            save(username, for: keyAccount)
            save(KeyAuthMode.login.rawValue, for: authModeAccount)
        case .register(let username, let password, let key):
            save(username, for: usernameAccount)
            save(password, for: passwordAccount)
            save(key, for: keyAccount)
            save(KeyAuthMode.login.rawValue, for: authModeAccount)
        }

        save(sessionToken, for: clientSessionAccount)
        clientSessionRevision += 1
        isActive = true
        statusLevel = .success
        if !silent {
            let haptic = UINotificationFeedbackGenerator()
            haptic.notificationOccurred(.success)
            message = "Access granted • \(state.subscription)"
        }
    }

    private func handleVerificationFailure(_ error: APIError, silent: Bool, verificationID: UUID) {
        activeVerificationID = nil
        isBusy = false
        if !silent { isLoadingScreen = false }

        switch error {
        case .message(let errorText):
            if !silent {
                isActive = false
                statusLevel = .error
                let haptic = UINotificationFeedbackGenerator()
                haptic.notificationOccurred(.error)
                message = errorText
            }
        case .revoked(let errorText):
            isActive = false
            delete(keyAccount)
            delete(usernameAccount)
            delete(passwordAccount)
            delete(clientSessionAccount)
            delete(expirationAccount)
            delete(expiryKnownAccount)
            delete(expiryPresentAccount)
            expirationDate = nil
            hasExpiryInformation = false
            expiryDateWasProvided = false
            statusLevel = .error
            if !silent {
                let haptic = UINotificationFeedbackGenerator()
                haptic.notificationOccurred(.error)
            }
            message = errorText
        }
    }

    private static func humanizeKeyAuthMessage(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = trimmed.lowercased()
        if lower.contains("hwid") && lower.contains("mismatch") {
            return "HWID mismatch — this key is bound to another iPhone. Request an HWID reset."
        }
        if lower.contains("key") && (lower.contains("doesn't exist") || lower.contains("not found") || lower.contains("invalid")) {
            return "Invalid license key — verify your EXTERNAL IPHONE key and try again."
        }
        if lower.contains("expired") {
            return "Subscription expired — renew your EXTERNAL IPHONE license."
        }
        if lower.contains("banned") || lower.contains("blacklisted") {
            return "Access suspended — this license or HWID has been blacklisted."
        }
        if lower.contains("logged in") {
            return "Authenticated with KeyAuth Cloud"
        }
        return trimmed.isEmpty ? "KeyAuth response received" : trimmed
    }

    private static func parseUnixTimestamp(_ raw: Any?) -> Date? {
        if let number = raw as? NSNumber {
            let val = number.doubleValue
            guard val > 0 else { return nil }
            return Date(timeIntervalSince1970: val > 10_000_000_000 ? val / 1000.0 : val)
        }
        if let str = raw as? String, let val = Double(str.trimmingCharacters(in: .whitespacesAndNewlines)), val > 0 {
            return Date(timeIntervalSince1970: val > 10_000_000_000 ? val / 1000.0 : val)
        }
        return nil
    }

    private static func urlFormEncode(_ string: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return string.addingPercentEncoding(withAllowedCharacters: allowed) ?? string
    }

    // MARK: - Keychain & Helpers

    private func string(for account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func save(_ value: String, for account: String) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(base as CFDictionary)
        var item = base
        item[kSecValueData as String] = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }

    private func delete(_ account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }

    private func revokeClientSession() {
        guard let token = string(for: clientSessionAccount),
              let url = URL(string: VesperStringVault.vesperDashClientSessionURL + "/logout") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 8
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        URLSession.shared.dataTask(with: request).resume()
    }

    private func sha256(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func deviceIdentifier() -> String {
        if let existing = string(for: deviceAccount, service: deviceService) { return existing }
        let vendorID = UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString
        save(vendorID, for: deviceAccount, service: deviceService)
        return vendorID
    }

    private func string(for account: String, service: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func save(_ value: String, for account: String, service: String) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(base as CFDictionary)
        var item = base
        item[kSecValueData as String] = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }
}

private enum APIError: Error {
    case message(String)
    case revoked(String)
}
