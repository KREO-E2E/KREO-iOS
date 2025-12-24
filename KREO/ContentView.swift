import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var model = ChatViewModel()
    @State private var selectedTab = 0
    private var chatBadge: String? {
        let count = model.unreadCount
        guard count > 0 else { return nil }
        return count > 99 ? "99+" : "\(count)"
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            ConnectionTabView(model: model)
                .tabItem {
                    Label("Connection", systemImage: "dot.radiowaves.left.and.right")
                }
                .tag(0)

            ChatTabView(model: model)
                .tabItem {
                    Label("Chat", systemImage: "message")
                }
                .badge(chatBadge)
                .tag(1)

            LogTabView(lines: model.logLines, isReady: model.isConnected && model.authed && model.joined)
                .tabItem {
                    Label("Log View", systemImage: "list.bullet.rectangle")
                }
                .tag(2)

            PGPKeyTabView(model: model)
                .tabItem {
                    Label("PGP Key", systemImage: "key")
                }
                .tag(3)

            SettingsTabView(model: model)
                .tabItem {
                    Label("Settings", systemImage: "gearshape")
                }
                .tag(4)
        }
        .task {
            if model.relayList.isEmpty {
                model.discoverRelays()
            }
            let isChat = selectedTab == 1
            model.isChatTabActive = isChat
            if isChat {
                model.markChatRead()
            }
        }
        .onChange(of: selectedTab) { _, newValue in
            let isChat = newValue == 1
            model.isChatTabActive = isChat
            if isChat {
                model.markChatRead()
            }
        }
    }
}

struct ChatTabView: View {
    @ObservedObject var model: ChatViewModel

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                StatusBanner(model: model)
                    .padding(.horizontal)

                if model.isConnected && model.authed && model.joined {
                    ChatHistoryView(lines: model.chatLines, autoScroll: model.chatAutoScroll)
                        .frame(maxHeight: .infinity)
                } else {
                    VStack(spacing: 8) {
                        Text("Connect and finish the challenge to start chatting.")
                            .foregroundStyle(.secondary)
                        Text("Go to the Connection tab to set up.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .padding(.horizontal)
                }
            }
            .navigationTitle("Chat")
            .navigationBarTitleDisplayMode(.inline)
            .safeAreaInset(edge: .bottom) {
                if model.isConnected && model.authed && model.joined {
                    MessageComposer(model: model)
                        .padding(.horizontal)
                        .padding(.top, 6)
                        .padding(.bottom, 8)
                        .background(Color(.systemBackground))
                }
            }
        }
    }
}

struct ConnectionTabView: View {
    @ObservedObject var model: ChatViewModel

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    ConnectionSection(model: model)
                    RelayDiscoverySection(model: model)
                    ChallengeSection(model: model)
                    StatusSection(model: model)
                    ConnectionActions(model: model)
                }
                .padding(.horizontal)
                .padding(.top)
            }
            .navigationTitle("Connection")
            .navigationBarTitleDisplayMode(.inline)
            .keyboardDismissButton()
        }
    }
}

struct LogTabView: View {
    let lines: [String]
    let isReady: Bool
    @State private var showLog = true

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                if isReady {
                    LogToggle(showLog: $showLog)
                        .padding(.horizontal)

                    if showLog {
                        LogView(lines: lines, autoScroll: true)
                            .frame(maxHeight: .infinity)
                    } else {
                        Text("Log hidden")
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                } else {
                    Text("Connect and complete the challenge to view logs.")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .padding(.top)
            .navigationTitle("Log View")
            .navigationBarTitleDisplayMode(.inline)
            .keyboardDismissButton()
        }
    }
}

struct PGPKeyTabView: View {
    @ObservedObject var model: ChatViewModel
    @State private var showingImporter = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox("Private Key") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(model.pgpPrivateKeyAvailable ? "Private key loaded" : "No private key imported")
                            .foregroundStyle(model.pgpPrivateKeyAvailable ? .green : .secondary)
                        if model.pgpPrivateKeyAvailable {
                            Text(model.pgpFingerprint.isEmpty ? "Fingerprint unavailable" : "Fingerprint: \(model.pgpFingerprint)")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                        HStack(spacing: 12) {
                            Button("Import Private Key") {
                                showingImporter = true
                            }
                            .buttonStyle(.borderedProminent)

                            Button("Clear Key") {
                                model.clearPrivateKey()
                            }
                            .buttonStyle(.bordered)
                            .disabled(!model.pgpPrivateKeyAvailable)
                        }
                    }
                }

                GroupBox("Public Key") {
                    VStack(alignment: .leading, spacing: 8) {
                        if model.pgpPrivateKeyAvailable && !model.pgpPublicKeyArmored.isEmpty {
                            TextEditor(text: $model.pgpPublicKeyArmored)
                                .frame(minHeight: 140)
                                .font(.system(.footnote, design: .monospaced))
                                .disabled(true)
                            HStack(spacing: 12) {
                                Button("Copy Public Key") {
                                    UIPasteboard.general.string = model.pgpPublicKeyArmored
                                }
                                .buttonStyle(.bordered)
                                Toggle("Use for registration", isOn: $model.usePublicKeyForRegistration)
                                    .toggleStyle(.switch)
                            }
                        } else if model.pgpPrivateKeyAvailable {
                            Text("Public key not available for this private key.")
                                .foregroundStyle(.secondary)
                        } else {
                            Text("Import a private key to derive the public key.")
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                if !model.pgpStatusMessage.isEmpty {
                    Text(model.pgpStatusMessage)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Spacer()
            }
            .padding()
            .navigationTitle("PGP Key")
            .navigationBarTitleDisplayMode(.inline)
            .keyboardDismissButton()
            .fileImporter(
                isPresented: $showingImporter,
                allowedContentTypes: [.data, .text],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    guard let url = urls.first else {
                        model.pgpStatusMessage = "No file selected."
                        return
                    }
                    let access = url.startAccessingSecurityScopedResource()
                    defer {
                        if access { url.stopAccessingSecurityScopedResource() }
                    }
                    do {
                        let data = try Data(contentsOf: url)
                        model.importPrivateKey(data: data)
                    } catch {
                        model.pgpStatusMessage = "Failed to read private key file."
                    }
                case .failure:
                    model.pgpStatusMessage = "Private key import canceled."
                }
            }
        }
    }
}

struct ConnectionSection: View {
    @ObservedObject var model: ChatViewModel

    var body: some View {
        GroupBox("Connection") {
            VStack(alignment: .leading, spacing: 8) {
                TextField("Server URL", text: $model.serverUrl)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .submitLabel(.done)
                TextField("Username", text: $model.username)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .submitLabel(.done)
                HStack(spacing: 8) {
                    TextField("Session ID", text: $model.sessionId)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .submitLabel(.done)
                    Button("Generate") {
                        model.generateSessionId()
                    }
                }
                HStack(spacing: 8) {
                    TextField("Passphrase (optional)", text: $model.passphrase)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .submitLabel(.done)
                    Button("Generate") {
                        model.generatePassphrase()
                    }
                }
                TextField("Nickname (optional)", text: $model.nickname)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .submitLabel(.done)
                TextField("Public key ID / fingerprint", text: $model.publicKeyId)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .submitLabel(.done)
            }
        }
    }
}

struct RegistrationSection: View {
    @ObservedObject var model: ChatViewModel

    var body: some View {
        GroupBox("Registration Public Key (optional)") {
            TextEditor(text: $model.registerPublicKey)
                .frame(minHeight: 90)
                .font(.system(.footnote, design: .monospaced))
        }
    }
}

struct StatusSection: View {
    @ObservedObject var model: ChatViewModel

    var body: some View {
        GroupBox("Status") {
            VStack(alignment: .leading, spacing: 6) {
                Text("Connected: \(model.isConnected ? "yes" : "no")")
                Text("Authed: \(model.authed ? "yes" : "no")")
                Text("Joined: \(model.joined ? "yes" : "no")")
                Text("Epoch: \(model.currentEpoch)")
                Text("Sender ID: \(model.senderId)")
                Text("Group key ready: \(model.groupKeyReady ? "yes" : "no")")
            }
        }
    }
}

struct ChallengeSection: View {
    @ObservedObject var model: ChatViewModel

    var body: some View {
        GroupBox("PGP Challenge") {
            VStack(alignment: .leading, spacing: 8) {
                if !model.pendingChallengeArmored.isEmpty {
                    HStack(alignment: .top, spacing: 8) {
                        TextEditor(text: $model.pendingChallengeArmored)
                            .frame(minHeight: 120)
                            .font(.system(.footnote, design: .monospaced))
                            .disabled(true)
                        Button("Copy") {
                            UIPasteboard.general.string = model.pendingChallengeArmored
                        }
                        .buttonStyle(.bordered)
                    }
                } else {
                    Text("No challenge yet.")
                        .foregroundStyle(.secondary)
                }

                if !model.pgpPrivateKeyAvailable {
                    Text("Import a private key in the PGP Key tab to decrypt here.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                SecureField("Private key passphrase (if any)", text: $model.pgpPassphrase)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .submitLabel(.done)

                HStack(spacing: 8) {
                    Button("Decrypt Challenge") {
                        model.decryptPendingChallenge()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.pendingChallengeArmored.isEmpty)

                    Button("Send Challenge Response") {
                        model.sendLoginChallengeResponse()
                    }
                    .buttonStyle(.bordered)
                    .disabled(model.pendingChallengeArmored.isEmpty)
                }

                if !model.pgpStatusMessage.isEmpty {
                    Text(model.pgpStatusMessage)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                TextField("Decrypted challenge response", text: $model.pendingChallengeResponse)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .submitLabel(.done)
            }
        }
    }
}

struct ConnectionActions: View {
    @ObservedObject var model: ChatViewModel

    var body: some View {
        HStack(spacing: 12) {
            Button(model.isConnected ? "Reconnect" : "Connect") {
                model.connect()
            }
            .buttonStyle(.borderedProminent)

            Button("Disconnect") {
                model.disconnect()
            }
            .buttonStyle(.bordered)
            .disabled(!model.isConnected)
        }
    }
}

struct LogToggle: View {
    @Binding var showLog: Bool

    var body: some View {
        Button(showLog ? "Hide Log" : "Show Log") {
            showLog.toggle()
        }
        .buttonStyle(.bordered)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct LogView: View {
    let lines: [String]
    let autoScroll: Bool

    var body: some View {
        LogScrollView(lines: lines, autoScroll: autoScroll)
    }
}

private struct LogScrollView: View {
    let lines: [String]
    let autoScroll: Bool

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                logList
            }
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .padding(.horizontal)
            .onChange(of: lines.count) { _, _ in
                guard autoScroll, let last = lines.indices.last else { return }
                proxy.scrollTo(last, anchor: .bottom)
            }
        }
    }

    private var logList: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(lines.indices, id: \.self) { index in
                Text(lines[index])
                    .font(.system(.footnote, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .id(index)
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }
}

struct MessageComposer: View {
    @ObservedObject var model: ChatViewModel

    var body: some View {
        HStack(spacing: 8) {
            TextField("Message", text: $model.messageInput)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .submitLabel(.send)
            Button("Send") {
                model.sendChatMessage()
            }
            .buttonStyle(.borderedProminent)
            .disabled(!model.joined || !model.groupKeyReady)
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(.secondarySystemBackground))
        )
    }
}

struct StatusBanner: View {
    @ObservedObject var model: ChatViewModel

    var body: some View {
        HStack(spacing: 12) {
            StatusPill(label: model.isConnected ? "Connected" : "Disconnected", isOn: model.isConnected)
            StatusPill(label: model.authed ? "Authed" : "Auth Pending", isOn: model.authed)
            StatusPill(label: model.joined ? "Joined" : "Not Joined", isOn: model.joined)
            Spacer()
        }
    }
}

struct StatusPill: View {
    let label: String
    let isOn: Bool

    var body: some View {
        Text(label)
            .font(.caption)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(isOn ? Color.green.opacity(0.2) : Color.secondary.opacity(0.2))
            .clipShape(Capsule())
    }
}

struct ChatHistoryView: View {
    let lines: [String]
    let autoScroll: Bool

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(spacing: 8) {
                    if lines.isEmpty {
                        Text("No messages yet.")
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        ForEach(lines.indices, id: \.self) { index in
                            let entry = ChatEntry(from: lines[index])
                            let previousLabel = index > 0 ? ChatEntry(from: lines[index - 1]).displayLabel : nil
                            let showLabel = entry.displayLabel != nil && entry.displayLabel != previousLabel
                            VStack(alignment: entry.isMe ? .trailing : .leading, spacing: 4) {
                                if showLabel, let label = entry.displayLabel {
                                    Text(label)
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                ChatBubble(text: entry.text, isMe: entry.isMe)
                            }
                            .frame(maxWidth: .infinity, alignment: entry.isMe ? .trailing : .leading)
                            .id(index)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .topLeading)
                .padding(.horizontal)
                .padding(.vertical, 12)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(
                        LinearGradient(
                            colors: [Color(.secondarySystemBackground), Color(.systemBackground)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
            )
            .padding(.horizontal)
            .onChange(of: lines.count) { _, _ in
                guard autoScroll, let last = lines.indices.last else { return }
                proxy.scrollTo(last, anchor: .bottom)
            }
        }
    }
}

struct ChatBubble: View {
    let text: String
    let isMe: Bool

    var body: some View {
        HStack {
            if isMe { Spacer() }
            Text(text)
                .foregroundStyle(isMe ? .white : .primary)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(isMe ? Color.accentColor : Color(.systemBackground))
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.black.opacity(isMe ? 0 : 0.08))
                )
                .shadow(color: Color.black.opacity(isMe ? 0.12 : 0.06), radius: 2, x: 0, y: 1)
            if !isMe { Spacer() }
        }
    }
}

struct ChatEntry {
    let text: String
    let isMe: Bool
    let displayLabel: String?

    init(from line: String) {
        if line.hasPrefix("me ") {
            isMe = true
            text = String(line.dropFirst(3))
            displayLabel = "You"
        } else {
            isMe = false
            let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            if parts.count == 2 {
                displayLabel = String(parts[0])
                text = String(parts[1])
            } else {
                displayLabel = nil
                text = line
            }
        }
    }
}

struct SettingsTabView: View {
    @ObservedObject var model: ChatViewModel

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                GroupBox("Relay") {
                    VStack(alignment: .leading, spacing: 8) {
                        if !model.relayList.isEmpty {
                            Picker("Relay", selection: $model.serverUrl) {
                                ForEach(model.relayList, id: \.self) { relay in
                                    Text(relay).tag(relay)
                                }
                            }
                            .pickerStyle(.menu)
                        } else {
                            Text("No relays loaded yet.")
                                .foregroundStyle(.secondary)
                        }
                        Button("Refresh Relay Status") {
                            model.refreshRelayStatuses()
                        }
                        .buttonStyle(.bordered)
                    }
                }
                .padding(.horizontal)

                GroupBox("Chat") {
                    Toggle("Auto-scroll messages", isOn: $model.chatAutoScroll)
                        .toggleStyle(.switch)
                    Toggle("Show encrypted payloads in log", isOn: $model.showEncrypted)
                        .toggleStyle(.switch)
                }
                .padding(.horizontal)

                GroupBox("Commands") {
                    VStack(alignment: .leading, spacing: 8) {
                        Button("Rekey Now") {
                            model.manualRekey()
                        }
                        .buttonStyle(.borderedProminent)
                        Button("Log Safety Code") {
                            model.logSafetyCode()
                        }
                        .buttonStyle(.bordered)
                        Button("Log Peers") {
                            model.logPeers()
                        }
                        .buttonStyle(.bordered)
                        Button("Log Session") {
                            model.logSessionInfo()
                        }
                        .buttonStyle(.bordered)
                        Button("Log Relay Info") {
                            model.logRelayInfo()
                        }
                        .buttonStyle(.bordered)
                    }
                }
                .padding(.horizontal)

                Spacer()

                HStack(spacing: 4) {
                    Text("Made with")
                    Image(systemName: "heart.fill")
                    Text("by AI, Karmakido and Lndr")
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
                .padding(.bottom, 8)
            }
            .padding(.top)
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

struct RelayDiscoverySection: View {
    @ObservedObject var model: ChatViewModel

    var body: some View {
        GroupBox("Relay Discovery") {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Button("Discover Relays") {
                        model.discoverRelays()
                    }
                    .buttonStyle(.borderedProminent)
                    Button("Refresh Status") {
                        model.refreshRelayStatuses()
                    }
                    .buttonStyle(.bordered)
                }

                if model.relayList.isEmpty {
                    Text("No relays loaded yet.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.relayList, id: \.self) { relay in
                        HStack {
                            RelayStatusDot(status: model.relayStatuses[relay] ?? .unknown)
                            Text(relay)
                                .font(.footnote)
                                .lineLimit(1)
                            Spacer()
                            Button("Use") {
                                model.useRelay(relay)
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                }
            }
        }
    }
}

struct RelayStatusDot: View {
    let status: RelayHealth

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 10, height: 10)
    }

    private var color: Color {
        switch status {
        case .ok:
            return .green
        case .failed:
            return .red
        case .unknown:
            return .gray
        }
    }
}

extension View {
    func keyboardDismissButton() -> some View {
        toolbar {
            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button("Done") {
                    hideKeyboard()
                }
            }
        }
    }
}

private func hideKeyboard() {
    UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
}

#Preview {
    ContentView()
}
