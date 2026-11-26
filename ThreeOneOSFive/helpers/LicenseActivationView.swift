// ThreeOneOSFive/helpers/LicenseActivationView.swift
import SwiftUI
import UIKit

struct LicenseActivationView: View {
    @ObservedObject var manager: LicenseManager
    @State private var key = ""
    @State private var username = ""
    @State private var password = ""
    @State private var showPassword = false
    @State private var showLicenseKey = true
    @State private var copiedHwidNotice = false
    @State private var introVisible = false
    @State private var logoBreathing = false
    @State private var ringRotating = false
    @FocusState private var focusedField: FocusField?

    private enum FocusField: Hashable {
        case key
        case username
        case password
    }

    var body: some View {
        NavigationStack {
            ZStack {
                LoginBackdrop()
                    .ignoresSafeArea()

                Color.black.opacity(0.22)
                    .ignoresSafeArea()

                ScrollViewReader { proxy in
                    ScrollView(showsIndicators: false) {
                        VStack(spacing: 0) {
                            Spacer(minLength: 22)

                            topTelemetryBar
                                .padding(.horizontal, 20)
                                .padding(.bottom, 18)
                                .opacity(introVisible ? 1 : 0)

                            brandMark
                                .padding(.bottom, 16)

                            VStack(spacing: 6) {
                                Text("WALTER X CHEAT")
                                    .font(.system(size: 24, weight: .black, design: .rounded))
                                    .tracking(1.4)
                                    .foregroundStyle(.white)
                                    .lineLimit(1)
                                    .minimumScaleFactor(0.75)

                                HStack(spacing: 6) {
                                    Image(systemName: "checkmark.shield.fill")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundStyle(Color(red: 0.22, green: 0.94, blue: 0.62))
                                    Text("WALTER X CHEAT • KEYAUTH CLOUD")
                                        .font(.system(size: 10, weight: .black, design: .rounded))
                                        .tracking(1.6)
                                        .foregroundStyle(.white.opacity(0.76))
                                }

                                Text("EXTERNAL IPHONE • \(AppInfo.displayMachineName) • iOS \(AppInfo.osVersion)")
                                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                                    .tracking(0.5)
                                    .foregroundStyle(.white.opacity(0.45))
                                    .padding(.top, 2)
                            }
                            .padding(.horizontal, 24)
                            .opacity(introVisible ? 1 : 0)
                            .offset(y: introVisible ? 0 : 12)
                            .padding(.bottom, 20)

                            activationCard
                                .padding(.horizontal, 18)
                                .opacity(introVisible ? 1 : 0)
                                .offset(y: introVisible ? 0 : 20)
                                .id("activation-card")

                            hwidFooterCard
                                .padding(.horizontal, 18)
                                .padding(.top, 14)
                                .opacity(introVisible ? 1 : 0)

                            Text("KEYAUTH v1.2 • HARDWARE-LOCKED AUTHENTICATION")
                                .font(.system(size: 9, weight: .bold, design: .rounded))
                                .tracking(0.9)
                                .foregroundStyle(.white.opacity(0.34))
                                .padding(.top, 16)
                                .padding(.horizontal, 20)

                            Spacer(minLength: 28)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.bottom, 24)
                    }
                    .scrollDismissesKeyboard(.interactively)
                    .onChange(of: focusedField) { field in
                        guard field != nil else { return }
                        withAnimation(.easeOut(duration: 0.25)) {
                            proxy.scrollTo("activation-card", anchor: .center)
                        }
                    }
                }
            }
            .onAppear {
                if key.isEmpty, let savedKey = manager.rememberedKey() {
                    key = savedKey
                }
                if username.isEmpty, let savedUser = manager.rememberedUsername() {
                    username = savedUser
                }
                if password.isEmpty, let savedPass = manager.rememberedPassword() {
                    password = savedPass
                }
                manager.pingServerHandshake()
                withAnimation(.easeOut(duration: 0.65)) {
                    introVisible = true
                }
                logoBreathing = true
                ringRotating = true
            }
        }
        .preferredColorScheme(.dark)
    }

    private var topTelemetryBar: some View {
        HStack(spacing: 10) {
            HStack(spacing: 6) {
                Circle()
                    .fill(manager.serverOnline ? Color(red: 0.20, green: 0.92, blue: 0.56) : Color.orange)
                    .frame(width: 7, height: 7)
                    .shadow(color: manager.serverOnline ? Color.green.opacity(0.8) : Color.orange.opacity(0.8), radius: 5)
                Text(manager.serverOnline ? "GATEWAY ONLINE" : "KEYAUTH READY")
                    .font(.system(size: 9, weight: .black, design: .rounded))
                    .tracking(0.8)
                    .foregroundStyle(.white.opacity(0.85))
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Color.white.opacity(0.06), in: Capsule())
            .overlay(Capsule().stroke(.white.opacity(0.14), lineWidth: 1))

            Spacer()

            if let online = manager.onlineUsersCount, !online.isEmpty {
                HStack(spacing: 5) {
                    Image(systemName: "person.2.fill")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(AppTheme.accent.opacity(0.8))
                    Text("\(online) ACTIVE")
                        .font(.system(size: 9, weight: .black, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.78))
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(Color.white.opacity(0.06), in: Capsule())
                .overlay(Capsule().stroke(.white.opacity(0.14), lineWidth: 1))
            }
        }
    }

    private var brandMark: some View {
        ZStack {
            Circle()
                .fill(AppTheme.accent.opacity(0.16))
                .frame(width: 124, height: 124)
                .blur(radius: 24)

            Circle()
                .stroke(AppTheme.accent.opacity(0.24), lineWidth: 1)
                .frame(width: 108, height: 108)

            Circle()
                .trim(from: 0.08, to: 0.74)
                .stroke(
                    LinearGradient(
                        colors: [AppTheme.accent, Color(red: 0.22, green: 0.94, blue: 0.62), .clear],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    style: StrokeStyle(lineWidth: 2.5, lineCap: .round)
                )
                .frame(width: 116, height: 116)
                .rotationEffect(.degrees(ringRotating ? 360 : 0))
                .animation(.linear(duration: 12).repeatForever(autoreverses: false), value: ringRotating)

            Image("VesperEmblem")
                .resizable()
                .scaledToFill()
                .frame(width: 82, height: 82)
                .clipShape(Circle())
                .overlay(Circle().stroke(AppTheme.accent.opacity(0.85), lineWidth: 1.5))
                .shadow(color: AppTheme.accent.opacity(logoBreathing ? 0.36 : 0.12), radius: logoBreathing ? 20 : 10)
        }
        .scaleEffect(logoBreathing ? 1.02 : 0.96)
        .animation(.easeInOut(duration: 2.4).repeatForever(autoreverses: true), value: logoBreathing)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("External iPhone KeyAuth")
    }

    private var modeSelector: some View {
        HStack(spacing: 6) {
            ForEach(KeyAuthMode.allCases) { mode in
                let isSelected = manager.authMode == mode
                Button {
                    let impact = UIImpactFeedbackGenerator(style: .light)
                    impact.impactOccurred()
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.82)) {
                        manager.authMode = mode
                        focusedField = nil
                    }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: mode.icon)
                            .font(.system(size: 10, weight: .bold))
                        Text(mode.title)
                            .font(.system(size: 10, weight: .black, design: .rounded))
                            .tracking(0.6)
                            .lineLimit(1)
                            .minimumScaleFactor(0.75)
                    }
                    .foregroundStyle(isSelected ? Color.black : Color.white.opacity(0.65))
                    .frame(maxWidth: .infinity, minHeight: 38)
                    .background(
                        isSelected ? Color.white : Color.white.opacity(0.04),
                        in: RoundedRectangle(cornerRadius: 11, style: .continuous)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 11, style: .continuous)
                            .stroke(isSelected ? Color.white : Color.white.opacity(0.08), lineWidth: 1)
                    )
                }
                .buttonStyle(.plain)
            }
        }
        .padding(5)
        .background(Color.black.opacity(0.55), in: RoundedRectangle(cornerRadius: 15, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 15, style: .continuous).stroke(.white.opacity(0.12), lineWidth: 1))
    }

    private var activationCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(statusBadgeColor)
                        .frame(width: 44, height: 44)
                    Image(systemName: statusIconName)
                        .font(.system(size: 17, weight: .black))
                        .foregroundStyle(Color.black)
                        .rotationEffect(.degrees(manager.isBusy ? 180 : 0))
                        .animation(.easeInOut(duration: 0.35), value: manager.isBusy)
                }

                VStack(alignment: .leading, spacing: 3) {
                    Text(headerTitleText)
                        .font(.system(size: 14, weight: .black, design: .rounded))
                        .tracking(0.4)
                        .foregroundStyle(.white)
                    Text("WALTER X CHEAT • KEYAUTH 1.2")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .tracking(1.0)
                        .foregroundStyle(.white.opacity(0.60))
                }
                Spacer(minLength: 0)
                Text(manager.authMode.rawValue)
                    .font(.system(size: 9, weight: .black, design: .monospaced))
                    .tracking(0.8)
                    .foregroundStyle(.black)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 5)
                    .background(Color.white.opacity(0.92), in: Capsule())
            }

            modeSelector

            Group {
                switch manager.authMode {
                case .license:
                    licenseKeySection
                case .login:
                    accountCredentialsSection(includeLicenseField: false)
                case .register:
                    accountCredentialsSection(includeLicenseField: true)
                }
            }
            .transition(.opacity.combined(with: .move(edge: .top)))

            Button(action: performSubmit) {
                HStack(spacing: 10) {
                    if manager.isBusy {
                        ProgressView().tint(AppTheme.ink)
                    } else {
                        Image(systemName: submitButtonIcon)
                            .font(.system(size: 15, weight: .black))
                    }
                    Text(submitButtonTitle)
                        .font(.system(size: 13, weight: .black, design: .rounded))
                        .tracking(0.7)
                }
                .foregroundStyle(AppTheme.ink)
                .frame(maxWidth: .infinity, minHeight: 54)
                .background(
                    LinearGradient(
                        colors: [Color.white, Color.white.opacity(0.92)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    in: RoundedRectangle(cornerRadius: 16, style: .continuous)
                )
                .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(.white.opacity(0.24), lineWidth: 1))
                .shadow(color: Color.white.opacity(0.22), radius: 14, y: 5)
            }
            .buttonStyle(.plain)
            .disabled(!canSubmit || manager.isBusy)
            .opacity((!canSubmit || manager.isBusy) ? 0.50 : 1)
            .animation(.easeOut(duration: 0.18), value: manager.isBusy)

            if let message = manager.message {
                statusBanner(message: message)
            }

            HStack {
                Text("Need a license or HWID reset?")
                    .foregroundStyle(.white.opacity(0.62))
                Spacer()
                Button {
                    if let url = URL(string: "https://www.instagram.com/yooo_walter/") {
                        UIApplication.shared.open(url)
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "camera.fill")
                            .font(.system(size: 10, weight: .bold))
                        Text("INSTAGRAM @YOOO_WALTER")
                            .font(.system(size: 10, weight: .black, design: .rounded))
                            .tracking(0.6)
                    }
                    .foregroundStyle(.white)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.white.opacity(0.10), in: Capsule())
                    .overlay(Capsule().stroke(.white.opacity(0.20), lineWidth: 1))
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("license-contact-owner")
            }
            .font(.system(size: 11, weight: .semibold, design: .rounded))
        }
        .padding(20)
        .background(.ultraThinMaterial.opacity(0.78), in: RoundedRectangle(cornerRadius: 24, style: .continuous))
        .background(Color.black.opacity(0.92), in: RoundedRectangle(cornerRadius: 24, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .stroke(
                    LinearGradient(
                        colors: [AppTheme.accent.opacity(0.65), .white.opacity(0.12), AppTheme.accent.opacity(0.24)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 1
                )
        )
        .shadow(color: .black.opacity(0.38), radius: 22, y: 12)
        .animation(.easeOut(duration: 0.22), value: manager.message)
    }

    private var licenseKeySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("KEYAUTH LICENSE KEY")
                    .font(.system(size: 9, weight: .black, design: .rounded))
                    .tracking(1.4)
                    .foregroundStyle(.white.opacity(0.78))
                Spacer()
                Button {
                    if let pasted = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines),
                       !pasted.isEmpty {
                        key = pasted
                        let impact = UIImpactFeedbackGenerator(style: .rigid)
                        impact.impactOccurred()
                    }
                } label: {
                    Label("PASTE", systemImage: "doc.on.clipboard.fill")
                        .font(.system(size: 9, weight: .black, design: .rounded))
                        .tracking(0.6)
                        .foregroundStyle(.white)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.white.opacity(0.12), in: Capsule())
                }
                .buttonStyle(.plain)
            }

            HStack(spacing: 10) {
                Image(systemName: "key.horizontal.fill")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundStyle(focusedField == .key ? AppTheme.accent : .white.opacity(0.46))

                Group {
                    if showLicenseKey {
                        TextField("KEYAUTH-XXXX-XXXX-XXXX", text: $key)
                    } else {
                        SecureField("KEYAUTH-XXXX-XXXX-XXXX", text: $key)
                    }
                }
                .focused($focusedField, equals: .key)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.done)
                .onSubmit { performSubmit() }
                .font(.system(size: 14, weight: .semibold, design: .monospaced))
                .foregroundStyle(.white)
                .tint(AppTheme.accent)
                .accessibilityIdentifier("license-field")

                if !key.isEmpty {
                    Button {
                        showLicenseKey.toggle()
                    } label: {
                        Image(systemName: showLicenseKey ? "eye.slash.fill" : "eye.fill")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(.white.opacity(0.55))
                    }
                    .buttonStyle(.plain)

                    Button {
                        key = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(.white.opacity(0.45))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 14)
            .frame(height: 52)
            .background(Color.black.opacity(0.45), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(focusedField == .key ? AppTheme.accent.opacity(0.90) : .white.opacity(0.14), lineWidth: focusedField == .key ? 1.4 : 1)
            )
        }
    }

    private func accountCredentialsSection(includeLicenseField: Bool) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Text("USERNAME")
                    .font(.system(size: 9, weight: .black, design: .rounded))
                    .tracking(1.4)
                    .foregroundStyle(.white.opacity(0.78))

                HStack(spacing: 10) {
                    Image(systemName: "person.fill")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundStyle(focusedField == .username ? AppTheme.accent : .white.opacity(0.46))

                    TextField("Enter KeyAuth username", text: $username)
                        .focused($focusedField, equals: .username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.next)
                        .onSubmit { focusedField = .password }
                        .font(.system(size: 14, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.white)
                        .tint(AppTheme.accent)
                }
                .padding(.horizontal, 14)
                .frame(height: 50)
                .background(Color.black.opacity(0.45), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .stroke(focusedField == .username ? AppTheme.accent.opacity(0.90) : .white.opacity(0.14), lineWidth: focusedField == .username ? 1.4 : 1)
                )
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("PASSWORD")
                    .font(.system(size: 9, weight: .black, design: .rounded))
                    .tracking(1.4)
                    .foregroundStyle(.white.opacity(0.78))

                HStack(spacing: 10) {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundStyle(focusedField == .password ? AppTheme.accent : .white.opacity(0.46))

                    Group {
                        if showPassword {
                            TextField("Enter password", text: $password)
                        } else {
                            SecureField("Enter password", text: $password)
                        }
                    }
                    .focused($focusedField, equals: .password)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .submitLabel(includeLicenseField ? .next : .done)
                    .onSubmit {
                        if includeLicenseField {
                            focusedField = .key
                        } else {
                            performSubmit()
                        }
                    }
                    .font(.system(size: 14, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.white)
                    .tint(AppTheme.accent)

                    Button {
                        showPassword.toggle()
                    } label: {
                        Image(systemName: showPassword ? "eye.slash.fill" : "eye.fill")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(.white.opacity(0.55))
                    }
                    .buttonStyle(.plain)
                }
                .padding(.horizontal, 14)
                .frame(height: 50)
                .background(Color.black.opacity(0.45), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .stroke(focusedField == .password ? AppTheme.accent.opacity(0.90) : .white.opacity(0.14), lineWidth: focusedField == .password ? 1.4 : 1)
                )
            }

            if includeLicenseField {
                licenseKeySection
            }
        }
    }

    private func statusBanner(message: String) -> some View {
        let tint = bannerTintColor
        return HStack(spacing: 10) {
            Image(systemName: bannerIconName)
                .font(.system(size: 14, weight: .black))
                .foregroundStyle(tint)
            Text(message)
                .font(.system(size: 12, weight: .bold, design: .rounded))
                .foregroundStyle(.white.opacity(0.95))
                .multilineTextAlignment(.leading)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 13, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).stroke(tint.opacity(0.42), lineWidth: 1))
        .transition(.opacity.combined(with: .move(edge: .top)))
    }

    private var hwidFooterCard: some View {
        HStack(spacing: 12) {
            Image(systemName: "cpu.fill")
                .font(.system(size: 15, weight: .bold))
                .foregroundStyle(.white.opacity(0.82))
                .frame(width: 36, height: 36)
                .background(Color.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 11, style: .continuous))

            VStack(alignment: .leading, spacing: 2) {
                Text("DEVICE HWID FINGERPRINT")
                    .font(.system(size: 8, weight: .black, design: .rounded))
                    .tracking(1.1)
                    .foregroundStyle(.white.opacity(0.54))
                Text(manager.activeHwidHash)
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundStyle(.white.opacity(0.88))
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
            }

            Spacer(minLength: 6)

            Button {
                UIPasteboard.general.string = manager.activeHwidHash
                let impact = UIImpactFeedbackGenerator(style: .light)
                impact.impactOccurred()
                withAnimation {
                    copiedHwidNotice = true
                }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) {
                    withAnimation {
                        copiedHwidNotice = false
                    }
                }
            } label: {
                Text(copiedHwidNotice ? "COPIED" : "COPY HWID")
                    .font(.system(size: 9, weight: .black, design: .rounded))
                    .tracking(0.6)
                    .foregroundStyle(copiedHwidNotice ? Color.black : Color.white)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .background(
                        copiedHwidNotice ? Color(red: 0.22, green: 0.94, blue: 0.62) : Color.white.opacity(0.10),
                        in: Capsule()
                    )
                    .overlay(Capsule().stroke(.white.opacity(0.18), lineWidth: 1))
            }
            .buttonStyle(.plain)
        }
        .padding(13)
        .background(Color.black.opacity(0.82), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(.white.opacity(0.12), lineWidth: 1))
    }

    private var canSubmit: Bool {
        switch manager.authMode {
        case .license:
            return !key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .login:
            return !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
                   !password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .register:
            return !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
                   !password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
                   !key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }

    private var headerTitleText: String {
        if manager.isBusy { return "AUTHENTICATING WITH KEYAUTH…" }
        switch manager.authMode {
        case .license: return "LICENSE AUTHENTICATION"
        case .login: return "ACCOUNT SIGN IN"
        case .register: return "ACTIVATE NEW ACCOUNT"
        }
    }

    private var submitButtonTitle: String {
        if manager.isBusy { return "HANDSHAKING WITH KEYAUTH…" }
        switch manager.authMode {
        case .license: return "AUTHENTICATE LICENSE"
        case .login: return "SIGN IN TO PANEL"
        case .register: return "REGISTER & ACTIVATE"
        }
    }

    private var submitButtonIcon: String {
        switch manager.authMode {
        case .license: return "bolt.shield.fill"
        case .login: return "arrow.right.circle.fill"
        case .register: return "person.badge.shield.checkmark.fill"
        }
    }

    private var statusBadgeColor: Color {
        switch manager.statusLevel {
        case .neutral, .verifying:
            return Color.white
        case .success:
            return Color(red: 0.22, green: 0.94, blue: 0.62)
        case .warning:
            return Color.orange
        case .error:
            return Color(red: 1.0, green: 0.32, blue: 0.36)
        }
    }

    private var statusIconName: String {
        if manager.isBusy { return "arrow.triangle.2.circlepath" }
        switch manager.statusLevel {
        case .neutral, .verifying: return "lock.shield.fill"
        case .success: return "checkmark.shield.fill"
        case .warning: return "exclamationmark.shield.fill"
        case .error: return "xmark.shield.fill"
        }
    }

    private var bannerTintColor: Color {
        switch manager.statusLevel {
        case .neutral, .verifying: return AppTheme.accent
        case .success: return Color(red: 0.22, green: 0.94, blue: 0.62)
        case .warning: return Color.orange
        case .error: return Color(red: 1.0, green: 0.34, blue: 0.38)
        }
    }

    private var bannerIconName: String {
        switch manager.statusLevel {
        case .neutral, .verifying: return "shield.lefthalf.filled"
        case .success: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .error: return "xmark.octagon.fill"
        }
    }

    private func performSubmit() {
        focusedField = nil
        let impact = UIImpactFeedbackGenerator(style: .medium)
        impact.impactOccurred()
        switch manager.authMode {
        case .license:
            manager.activate(key: key)
        case .login:
            manager.login(username: username, password: password)
        case .register:
            manager.register(username: username, password: password, key: key)
        }
    }
}

struct LoginBackdrop: View {
    @State private var drift = false

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color.black, Color(red: 0.03, green: 0.03, blue: 0.05), Color.black],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )

            Circle()
                .fill(AppTheme.accent.opacity(0.14))
                .frame(width: 270, height: 270)
                .blur(radius: 56)
                .offset(x: drift ? 138 : -128, y: drift ? -265 : -205)

            Circle()
                .fill(Color(red: 0.22, green: 0.94, blue: 0.62).opacity(0.08))
                .frame(width: 230, height: 230)
                .blur(radius: 54)
                .offset(x: drift ? -130 : 118, y: drift ? 285 : 225)
        }
        .animation(.easeInOut(duration: 8).repeatForever(autoreverses: true), value: drift)
        .onAppear { drift = true }
    }
}
