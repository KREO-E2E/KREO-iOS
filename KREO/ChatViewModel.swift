import Foundation
import CryptoKit
import Combine
import ObjectivePGP

@MainActor
final class ChatViewModel: NSObject, ObservableObject {
    @Published var serverUrl: String = "ws://localhost:6969"
    @Published var username: String = ""
    @Published var sessionId: String = ""
    @Published var passphrase: String = ""
    @Published var nickname: String = ""
    @Published var publicKeyId: String = ""
    @Published var registerPublicKey: String = ""

    @Published var logLines: [String] = []
    @Published var messageInput: String = ""
    @Published var unreadCount: Int = 0
    @Published var isChatTabActive: Bool = true

    @Published var isConnected: Bool = false
    @Published var authed: Bool = false
    @Published var joined: Bool = false
    @Published var pendingChallengeArmored: String = ""
    @Published var pendingChallengeResponse: String = ""
    @Published var currentEpoch: Int = 1
    @Published var senderId: String = ""
    @Published var groupKeyReady: Bool = false
    @Published var pgpPrivateKeyAvailable: Bool = false
    @Published var pgpPassphrase: String = ""
    @Published var pgpStatusMessage: String = ""
    @Published var pgpFingerprint: String = ""
    @Published var pgpPublicKeyArmored: String = ""
    @Published var usePublicKeyForRegistration: Bool = false
    @Published var chatLines: [String] = []
    @Published var chatAutoScroll: Bool = true
    @Published var showEncrypted: Bool = false
    @Published var relayList: [String] = []
    @Published var relayStatuses: [String: RelayHealth] = [:]
    @Published var connectedRelay: String = ""
    @Published var entryRelay: String = ""

    private let maxLogLines = 300
    private let maxChatLines = 300

    private let protocolVersion = "v1"
    private let clientVersion = "1.1.0"
    private let defaultRelayListUrl = "https://raw.githubusercontent.com/Lndr2501/KREO-Relays/refs/heads/main/relays.json"
    private let maxRelayStatusChecks = 20
    private var urlSession: URLSession?
    private var socketTask: URLSessionWebSocketTask?

    private var pendingChallengeId: String?
    private var identity = Identity.generate()
    private var groupKey: SymmetricKey?
    private var messageCounter: UInt64 = 0
    private var noncePrefix = Data.randomBytes(count: 4)
    private var peers: [String: Peer] = [:]
    private var seenCipher: [String: TimeInterval] = [:]
    private let maxSeen = 500
    private var lastSafetyCode: String = ""
    private var lastServerVersion: String = ""

    override init() {
        super.init()
        refreshPgpKeyStatus()
        discoverRelays()
    }

    func connect() {
        if isConnected {
            disconnect()
        }
        let normalizedServer = normalizeServer(serverUrl.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines))
        guard let url = URL(string: normalizedServer) else {
            appendLog("invalid server URL")
            return
        }
        username = username.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        sessionId = sessionId.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        passphrase = passphrase.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        nickname = nickname.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        publicKeyId = publicKeyId.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        registerPublicKey = registerPublicKey.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        if publicKeyId.isEmpty, !pgpFingerprint.isEmpty {
            publicKeyId = pgpFingerprint
        }
        if usePublicKeyForRegistration, !pgpPublicKeyArmored.isEmpty {
            registerPublicKey = pgpPublicKeyArmored
        } else {
            registerPublicKey = ""
        }

        guard !username.isEmpty else {
            appendLog("username required")
            return
        }
        guard !sessionId.isEmpty else {
            appendLog("session ID required")
            return
        }
        guard !publicKeyId.isEmpty else {
            appendLog("public key id / fingerprint required")
            return
        }

        serverUrl = normalizedServer
        nickname = sanitizeNick(nickname.isEmpty ? username : nickname)

        authed = false
        joined = false
        groupKeyReady = false
        pendingChallengeArmored = ""
        pendingChallengeResponse = ""
        pendingChallengeId = nil
        currentEpoch = 1
        identity = Identity.generate()
        senderId = identity.senderId
        groupKey = nil
        peers = [:]
        messageCounter = 0
        noncePrefix = Data.randomBytes(count: 4)
        chatLines = []
        seenCipher = [:]
        lastSafetyCode = ""
        lastServerVersion = ""

        let config = URLSessionConfiguration.default
        urlSession = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        socketTask = urlSession?.webSocketTask(with: url)
        socketTask?.resume()
        listen()
    }

    func disconnect() {
        socketTask?.cancel(with: .goingAway, reason: nil)
        socketTask = nil
        urlSession?.invalidateAndCancel()
        urlSession = nil
        isConnected = false
        chatLines = []
        seenCipher = [:]
        connectedRelay = ""
        appendLog("disconnected")
    }

    func discoverRelays() {
        Task { await fetchRelayList() }
    }

    func refreshRelayStatuses() {
        Task { await checkRelayHealth() }
    }

    func useRelay(_ relay: String) {
        serverUrl = relay
    }

    func logPeers() {
        let list = peers
            .filter { $0.value.epoch == currentEpoch }
            .map { id, peer in
                peer.nickname.isEmpty ? id : "\(id)|\(peer.nickname)"
            }
            .sorted()
        appendLog("peers \(list.count): \(list.joined(separator: ", "))")
    }

    func logSessionInfo() {
        appendLog("session \(sessionId) | epoch \(currentEpoch)")
    }

    func logRelayInfo() {
        let relay = connectedRelay.isEmpty ? serverUrl : connectedRelay
        let entry = entryRelay.isEmpty ? serverUrl : entryRelay
        appendLog("relay \(relay) | entry \(entry)")
    }

    func logSafetyCode() {
        appendLog("safety \(lastSafetyCode.isEmpty ? "-" : lastSafetyCode)")
    }

    func manualRekey() {
        startRekey(reason: "manual", targetEpoch: nil)
    }

    func generateSessionId() {
        sessionId = Data.randomBytes(count: 16).hexString
    }

    func generatePassphrase() {
        passphrase = Data.randomBytes(count: 24).base64EncodedString()
    }

    func sendLoginChallengeResponse() {
        guard let challengeId = pendingChallengeId else { return }
        let response = pendingChallengeResponse.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !response.isEmpty else { return }
        safeSend([
            "type": "login-response",
            "challenge_id": challengeId,
            "response": response
        ])
        pendingChallengeResponse = ""
    }

    func importPrivateKey(data: Data) {
        guard let keyString = String(data: data, encoding: .utf8) else {
            pgpStatusMessage = "Private key file is not valid text."
            return
        }
        let trimmed = keyString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            pgpStatusMessage = "Private key file is empty."
            return
        }
        if KeychainManager.saveString(trimmed, account: KeychainManager.privateKeyAccount) {
            pgpStatusMessage = "Private key saved to Keychain."
            refreshPgpKeyStatus()
        } else {
            pgpStatusMessage = "Failed to save private key."
        }
    }

    func clearPrivateKey() {
        if KeychainManager.delete(account: KeychainManager.privateKeyAccount) {
            pgpStatusMessage = "Private key removed."
        } else {
            pgpStatusMessage = "Failed to remove private key."
        }
        refreshPgpKeyStatus()
    }

    func decryptPendingChallenge() {
        let armored = pendingChallengeArmored.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !armored.isEmpty else {
            pgpStatusMessage = "No PGP challenge to decrypt."
            return
        }
        guard let keyString = KeychainManager.readString(account: KeychainManager.privateKeyAccount) else {
            pgpStatusMessage = "No private key found. Import one in the PGP Key tab."
            return
        }

        do {
            let keyData = Data(keyString.utf8)
            let keys = try ObjectivePGP.readKeys(from: keyData)

            let messageData: Data
            if let dearmored = try? Armor.readArmored(armored) {
                messageData = dearmored
            } else {
                messageData = Data(armored.utf8)
            }

            let passphrase = pgpPassphrase.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            let decrypted = try ObjectivePGP.decrypt(
                messageData,
                andVerifySignature: false,
                using: keys,
                passphraseForKey: { _ in
                    passphrase.isEmpty ? nil : passphrase
                }
            )

            let plaintext = String(data: decrypted, encoding: .utf8) ?? String(decoding: decrypted, as: UTF8.self)
            pendingChallengeResponse = plaintext.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            pgpStatusMessage = "Challenge decrypted."
        } catch {
            pgpStatusMessage = "Failed to decrypt challenge."
        }
    }

    func sendChatMessage() {
        let text = messageInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        if text.hasPrefix("/") {
            handleChatCommand(text)
            messageInput = ""
            return
        }
        guard joined, groupKeyReady else {
            appendLog("not ready to send")
            return
        }
        sendEncrypted(text)
        appendChat("me \(text)", isIncoming: false)
        messageInput = ""
    }

    private func listen() {
        socketTask?.receive { [weak self] result in
            guard let self else { return }
            Task { @MainActor in
                switch result {
                case .failure(let error):
                    self.appendLog("socket error: \(error.localizedDescription)")
                    self.isConnected = false
                case .success(let message):
                    switch message {
                    case .string(let text):
                        self.handleMessageText(text)
                    case .data(let data):
                        if let text = String(data: data, encoding: .utf8) {
                            self.handleMessageText(text)
                        }
                    @unknown default:
                        break
                    }
                }
                self.listen()
            }
        }
    }

    private func handleMessageText(_ text: String) {
        guard let data = text.data(using: .utf8) else { return }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        handleMessage(json)
    }

    private func handleMessage(_ msg: [String: Any]) {
        guard let type = msg["type"] as? String else { return }
        switch type {
        case "register-ok":
            appendLog("public key registered for \(msg["username"] as? String ?? "")")
            sendLoginInit()
        case "error":
            appendLog("error: \(msg["message"] as? String ?? "server error")")
        case "login-challenge":
            handleLoginChallenge(msg)
        case "login-success":
            authed = true
            appendLog("login success for \(msg["username"] as? String ?? "")")
            if let version = msg["server_version"] as? String, version != clientVersion {
                appendLog("server version \(version) differs from client \(clientVersion)")
            }
            if let version = msg["server_version"] as? String {
                lastServerVersion = version
            }
            safeSend([
                "type": "join",
                "session_id": sessionId
            ])
        case "joined":
            joined = true
            appendLog("joined session \(msg["session_id"] as? String ?? "")")
            startRekey(reason: "login", targetEpoch: nil)
        case "peer-joined":
            appendLog("peer joined \(msg["session_id"] as? String ?? "")")
            startRekey(reason: "peer-joined", targetEpoch: nil)
        case "peer-left":
            appendLog("peer left, rekeying")
            startRekey(reason: "peer-left", targetEpoch: nil)
        case "announce":
            handleAnnounce(msg)
        case "ciphertext":
            handleCiphertext(msg)
        default:
            break
        }
    }

    private func handleLoginChallenge(_ msg: [String: Any]) {
        if let challengeId = msg["challenge_id"] as? String {
            pendingChallengeId = challengeId
        } else if let challengeId = msg["challenge_id"] as? NSNumber {
            pendingChallengeId = challengeId.stringValue
        } else {
            pendingChallengeId = nil
        }
        pendingChallengeArmored = msg["armored"] as? String ?? ""
        appendLog("PGP challenge received; decrypt the armored message and paste plaintext below")
        if !pendingChallengeArmored.isEmpty {
            appendLog(pendingChallengeArmored)
        }
    }

    private func sendLoginInit() {
        safeSend([
            "type": "login-init",
            "username": username,
            "key_id": publicKeyId,
            "client_version": clientVersion
        ])
    }

    private func startRekey(reason: String, targetEpoch: Int?) {
        let nextEpoch = (targetEpoch ?? (currentEpoch + 1))
        currentEpoch = nextEpoch
        groupKey = nil
        groupKeyReady = false
        peers = [:]
        identity = Identity.generate()
        senderId = identity.senderId
        noncePrefix = Data.randomBytes(count: 4)
        messageCounter = 0
        seenCipher = [:]
        appendLog("[rekey] \(reason) -> epoch \(currentEpoch), sender \(senderId)")
        sendAnnounce(reason: reason)
    }

    private func sendAnnounce(reason: String) {
        let frame: [String: Any] = [
            "type": "announce",
            "session_id": sessionId,
            "public_key": identity.publicDer.base64EncodedString(),
            "epoch": currentEpoch,
            "reason": reason,
            "nickname": nickname,
            "username": username
        ]
        safeSend(frame)
    }

    private func handleAnnounce(_ msg: [String: Any]) {
        guard let publicKeyB64 = msg["public_key"] as? String,
              let publicDer = Data(base64Encoded: publicKeyB64) else {
            return
        }

        let peerId = senderIdFromPublic(publicDer)
        if peerId == identity.senderId { return }

        let peerEpoch = (msg["epoch"] as? NSNumber)?.intValue ?? 1
        let peerNick = sanitizeNick(msg["nickname"] as? String ?? "")
        appendLog("[announce] peer \(peerId) epoch \(peerEpoch) keylen \(publicDer.count)")

        if peerEpoch > currentEpoch {
            startRekey(reason: "adopt-peer-epoch", targetEpoch: peerEpoch)
        } else if peerEpoch < currentEpoch {
            sendAnnounce(reason: "epoch-ahead")
        }

        peers[peerId] = Peer(publicDer: publicDer, epoch: peerEpoch, nickname: peerNick)
        deriveGroupKey()
    }

    private func deriveGroupKey() {
        let activePeers = peers.filter { $0.value.epoch == currentEpoch }
        guard !activePeers.isEmpty else { return }

        let participants: [(id: String, publicDer: Data)] = [
            (identity.senderId, identity.publicDer),
        ] + activePeers.map { (id: $0.key, publicDer: $0.value.publicDer) }

        let sorted = participants.sorted { $0.id.localizedCompare($1.id) == .orderedAscending }
        let inputMaterial = sorted.reduce(Data()) { $0 + $1.publicDer }
        let saltData = Data(SHA256.hash(data: Data("\(sessionId)|\(passphrase)|\(currentEpoch)".utf8)))
        let info = Data("group-key".utf8) + Data(sessionId.utf8)
        let inputHash = SHA256.hash(data: inputMaterial)
        appendLog("[key-debug] salt \(saltData.hexString.prefix(16)) input \(Data(inputHash).hexString.prefix(16))")
        // Match Node client hkdfSync parameter order (ikm = saltData, salt = inputMaterial).
        let okm = hkdfSHA256(ikm: saltData, salt: inputMaterial, info: info, outputLength: 32)
        let derivedKey = SymmetricKey(data: okm)

        groupKey = derivedKey
        groupKeyReady = true
        messageCounter = 0

        let safetyCode = SHA256.hash(data: derivedKey.withUnsafeBytes { Data($0) })
        let safety = String(Data(safetyCode).hexString.prefix(16))
        lastSafetyCode = safety
        appendLog("[key] epoch \(currentEpoch) ready. safety code \(safety)")
    }

    private func hkdfSHA256(ikm: Data, salt: Data, info: Data, outputLength: Int) -> Data {
        let prk = HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: salt))
        let prkData = Data(prk)
        let prkKey = SymmetricKey(data: prkData)
        var okm = Data()
        var previous = Data()
        var counter: UInt8 = 1

        while okm.count < outputLength {
            var context = Data()
            context.append(previous)
            context.append(info)
            context.append(counter)
            let block = HMAC<SHA256>.authenticationCode(for: context, using: prkKey)
            previous = Data(block)
            okm.append(previous)
            counter &+= 1
        }

        return okm.prefix(outputLength)
    }

    private func sendEncrypted(_ plaintext: String) {
        guard let groupKey else { return }
        let counter = messageCounter
        messageCounter += 1

        let nonce = noncePrefix + counter.bigEndianData
        let aad = buildAad(senderId: identity.senderId, counter: counter)

        guard let aesNonce = try? AES.GCM.Nonce(data: nonce) else { return }
        let plaintextData = Data(plaintext.utf8)
        guard let sealed = try? AES.GCM.seal(plaintextData, using: groupKey, nonce: aesNonce, authenticating: aad) else {
            appendLog("failed to encrypt")
            return
        }

        let frame: [String: Any] = [
            "type": "ciphertext",
            "msg_id": UUID().uuidString,
            "session_id": sessionId,
            "sender_id": identity.senderId,
            "epoch": currentEpoch,
            "counter": counter,
            "nonce": sealed.nonce.data.base64EncodedString(),
            "tag": sealed.tag.base64EncodedString(),
            "ciphertext": sealed.ciphertext.base64EncodedString()
        ]
        safeSend(frame)
        markSeen(msgId: frame["msg_id"] as? String, senderId: identity.senderId, epoch: currentEpoch, counter: counter)
        if showEncrypted, let ciphertext = frame["ciphertext"] as? String {
            appendLog("[encrypted] \(ciphertext)")
        }
    }

    private func handleCiphertext(_ msg: [String: Any]) {
        guard let groupKey else { return }
        let epoch = (msg["epoch"] as? NSNumber)?.intValue ?? 0
        guard epoch == currentEpoch else {
            appendLog("received message for different epoch, ignoring")
            return
        }

        let sender = msg["sender_id"] as? String ?? ""
        guard let peer = peers[sender], peer.epoch == currentEpoch else {
            appendLog("unknown sender, request rekey")
            return
        }
        if isSeen(msg) { return }

        guard let nonceB64 = msg["nonce"] as? String,
              let tagB64 = msg["tag"] as? String,
              let ciphertextB64 = msg["ciphertext"] as? String,
              let nonce = Data(base64Encoded: nonceB64),
              let tag = Data(base64Encoded: tagB64),
              let ciphertext = Data(base64Encoded: ciphertextB64) else {
            return
        }

        let aad = buildAad(senderId: sender, counter: UInt64((msg["counter"] as? NSNumber)?.uint64Value ?? 0))

        guard let aesNonce = try? AES.GCM.Nonce(data: nonce) else { return }
        let sealed = try? AES.GCM.SealedBox(nonce: aesNonce, ciphertext: ciphertext, tag: tag)
        guard let sealed else { return }

        do {
            let plaintext = try AES.GCM.open(sealed, using: groupKey, authenticating: aad)
            let displayLabel = peer.nickname.isEmpty ? sender : "\(sender)|\(peer.nickname)"
            if showEncrypted, let cipherText = msg["ciphertext"] as? String {
                appendLog("[encrypted] \(cipherText)")
            }
            appendChat("\(displayLabel) \(String(decoding: plaintext, as: UTF8.self))", isIncoming: true)
        } catch {
            appendLog("failed to decrypt/authenticate message, rekey recommended")
        }
    }

    private func buildAad(senderId: String, counter: UInt64) -> Data {
        let counterData = counter.bigEndianData
        return Data(protocolVersion.utf8) + Data(sessionId.utf8) + Data(hexString: senderId) + counterData
    }

    private func senderIdFromPublic(_ publicDer: Data) -> String {
        let hash = SHA256.hash(data: publicDer)
        return Data(hash).hexString.prefix(16).lowercased()
    }

    private func isSeen(_ msg: [String: Any]) -> Bool {
        let msgId = msg["msg_id"] as? String
        let sender = msg["sender_id"] as? String ?? ""
        let epoch = (msg["epoch"] as? NSNumber)?.intValue ?? 0
        let counter = (msg["counter"] as? NSNumber)?.uint64Value ?? 0
        let key = msgId ?? "\(sender)|\(epoch)|\(counter)"
        if seenCipher[key] != nil { return true }
        markSeen(msgId: msgId, senderId: sender, epoch: epoch, counter: counter)
        return false
    }

    private func markSeen(msgId: String?, senderId: String, epoch: Int, counter: UInt64) {
        let key = msgId ?? "\(senderId)|\(epoch)|\(counter)"
        seenCipher[key] = Date().timeIntervalSince1970
        if seenCipher.count > maxSeen {
            let overflow = seenCipher.count - maxSeen
            if overflow > 0 {
                for key in seenCipher.keys.prefix(overflow) {
                    seenCipher.removeValue(forKey: key)
                }
            }
        }
    }

    private func safeSend(_ obj: [String: Any]) {
        guard let socketTask else {
            appendLog("not connected")
            return
        }
        guard let data = try? JSONSerialization.data(withJSONObject: obj) else { return }
        socketTask.send(.data(data)) { error in
            guard let error else { return }
            let message = error.localizedDescription
            Task { @MainActor in
                self.appendLog("send error: \(message)")
            }
        }
    }

    private func appendLog(_ line: String) {
        logLines.append(line)
        if logLines.count > maxLogLines {
            logLines.removeFirst(logLines.count - maxLogLines)
        }
    }

    func markChatRead() {
        unreadCount = 0
    }

    private func appendChat(_ line: String, isIncoming: Bool) {
        chatLines.append(line)
        if chatLines.count > maxChatLines {
            chatLines.removeFirst(chatLines.count - maxChatLines)
        }
        if isIncoming && !isChatTabActive {
            unreadCount += 1
        }
    }

    private func handleChatCommand(_ text: String) {
        let parts = text.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        let command = parts.first?.lowercased() ?? ""
        switch command {
        case "/relay":
            let relay = connectedRelay.isEmpty ? serverUrl : connectedRelay
            let entry = entryRelay.isEmpty ? serverUrl : entryRelay
            appendChat("system relay \(relay) | entry \(entry)", isIncoming: false)
        default:
            appendChat("system unknown command: \(text)", isIncoming: false)
        }
    }

    private func sanitizeNick(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let limited = String(trimmed.prefix(32))
        let isAscii = limited.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value <= 0x7E }
        return isAscii ? limited : ""
    }

    private func refreshPgpKeyStatus() {
        pgpPrivateKeyAvailable = KeychainManager.readString(account: KeychainManager.privateKeyAccount) != nil
        updatePgpFingerprint()
        updatePgpPublicKey()
    }

    private func updatePgpFingerprint() {
        guard let keyString = KeychainManager.readString(account: KeychainManager.privateKeyAccount) else {
            pgpFingerprint = ""
            return
        }
        do {
            let keys = try ObjectivePGP.readKeys(from: Data(keyString.utf8))
            if let key = keys.first {
                if let secret = key.secretKey {
                    pgpFingerprint = secret.fingerprint.description
                } else if let pub = key.publicKey {
                    pgpFingerprint = pub.fingerprint.description
                } else {
                    pgpFingerprint = ""
                }
            } else {
                pgpFingerprint = ""
            }
        } catch {
            pgpFingerprint = ""
        }
    }

    private func updatePgpPublicKey() {
        guard let keyString = KeychainManager.readString(account: KeychainManager.privateKeyAccount) else {
            pgpPublicKeyArmored = ""
            return
        }
        do {
            let keys = try ObjectivePGP.readKeys(from: Data(keyString.utf8))
            guard let key = keys.first else {
                pgpPublicKeyArmored = ""
                return
            }
            let keyring = Keyring()
            keyring.import(keys: keys)
            if let publicData = try? keyring.exportKeys(of: .public) {
                pgpPublicKeyArmored = Armor.armored(publicData, as: .publicKey)
            } else if let publicData = try? key.export(keyType: .public) {
                pgpPublicKeyArmored = Armor.armored(publicData, as: .publicKey)
            } else if let armoredData = keyring.export(key: key, armored: true),
                      let armored = String(data: armoredData, encoding: .utf8) {
                pgpPublicKeyArmored = armored
            } else {
                pgpPublicKeyArmored = ""
            }
        } catch {
            pgpPublicKeyArmored = ""
        }
    }

    private func normalizeServer(_ url: String) -> String {
        if url.hasPrefix("ws://") || url.hasPrefix("wss://") { return url }
        return "ws://\(url)"
    }

    private func fetchRelayList() async {
        guard let url = URL(string: defaultRelayListUrl) else { return }
        do {
            var request = URLRequest(url: url)
            request.cachePolicy = .reloadIgnoringLocalCacheData
            let (data, _) = try await URLSession.shared.data(for: request)
            let decoded = try JSONDecoder().decode(RelayListResponse.self, from: data)
            await MainActor.run {
                relayList = decoded.relays.sorted(by: relaySort)
                if entryRelay.isEmpty, let first = relayList.first {
                    entryRelay = first
                }
            }
            await checkRelayHealth()
        } catch {
            appendLog("relay discovery failed")
        }
    }

    private func relaySort(_ lhs: String, _ rhs: String) -> Bool {
        let leftHost = relayHost(lhs)
        let rightHost = relayHost(rhs)
        let leftDomain = baseDomain(from: leftHost)
        let rightDomain = baseDomain(from: rightHost)
        if leftDomain != rightDomain {
            return leftDomain < rightDomain
        }
        if leftHost != rightHost {
            return leftHost < rightHost
        }
        return lhs < rhs
    }

    private func relayHost(_ relay: String) -> String {
        if let url = URL(string: relay), let host = url.host {
            return host
        }
        let stripped = relay.replacingOccurrences(of: "wss://", with: "")
            .replacingOccurrences(of: "ws://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .replacingOccurrences(of: "https://", with: "")
        return stripped.split(separator: "/").first.map(String.init) ?? relay
    }

    private func baseDomain(from host: String) -> String {
        let parts = host.split(separator: ".")
        guard parts.count >= 2 else { return host }
        return "\(parts[parts.count - 2]).\(parts[parts.count - 1])"
    }

    private func checkRelayHealth() async {
        let relays = relayList
        if relays.isEmpty { return }
        var results: [String: RelayHealth] = [:]
        let limit = min(relays.count, maxRelayStatusChecks)
        await withTaskGroup(of: (String, RelayHealth).self) { group in
            for relay in relays.prefix(limit) {
                group.addTask {
                    let health = await self.checkHealth(for: relay)
                    return (relay, health)
                }
            }
            for await (relay, status) in group {
                results[relay] = status
            }
        }
        await MainActor.run {
            relayStatuses.merge(results) { _, new in new }
        }
    }

    private func checkHealth(for relay: String) async -> RelayHealth {
        guard let url = URL(string: "\(toHttp(relay))/health") else { return .unknown }
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            let response = try JSONDecoder().decode(HealthResponse.self, from: data)
            return response.status == "ok" ? .ok : .failed
        } catch {
            return .failed
        }
    }

    private func toHttp(_ url: String) -> String {
        if url.hasPrefix("wss://") { return "https://\(url.dropFirst(6))" }
        if url.hasPrefix("ws://") { return "http://\(url.dropFirst(5))" }
        if url.hasPrefix("http://") || url.hasPrefix("https://") { return url }
        return "http://\(url)"
    }
}

enum RelayHealth: String {
    case unknown
    case ok
    case failed
}

struct RelayListResponse: Decodable {
    let relays: [String]
}

struct HealthResponse: Decodable {
    let status: String
}

extension ChatViewModel: URLSessionWebSocketDelegate {
    nonisolated func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        Task { @MainActor in
            self.isConnected = true
            self.connectedRelay = self.serverUrl
            if self.entryRelay.isEmpty {
                self.entryRelay = self.serverUrl
            }
            self.appendLog("connected \(self.serverUrl), user \(self.username), session \(self.sessionId)")
            if !self.registerPublicKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                self.safeSend([
                    "type": "register",
                    "username": self.username,
                    "key_id": self.publicKeyId,
                    "public_key": self.registerPublicKey
                ])
            } else {
                self.sendLoginInit()
            }
        }
    }

    nonisolated func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        Task { @MainActor in
            self.isConnected = false
            self.appendLog("disconnected from relay")
        }
    }
}

struct Identity {
    let privateKey: Curve25519.KeyAgreement.PrivateKey
    let publicDer: Data
    let senderId: String

    static func generate() -> Identity {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let rawPublic = privateKey.publicKey.rawRepresentation
        let publicDer = Data.x25519PublicKeyToSPKI(rawPublic)
        let hash = SHA256.hash(data: publicDer)
        let senderId = Data(hash).hexString.prefix(16).lowercased()
        return Identity(privateKey: privateKey, publicDer: publicDer, senderId: senderId)
    }
}

struct Peer {
    let publicDer: Data
    let epoch: Int
    let nickname: String
}

extension Data {
    static func + (lhs: Data, rhs: Data) -> Data {
        var data = lhs
        data.append(rhs)
        return data
    }

    static func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        for i in 0..<count { bytes[i] = UInt8.random(in: 0...255) }
        return Data(bytes)
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    init(hexString: String) {
        var data = Data()
        var buffer = ""
        for char in hexString {
            buffer.append(char)
            if buffer.count == 2 {
                if let byte = UInt8(buffer, radix: 16) {
                    data.append(byte)
                }
                buffer = ""
            }
        }
        self = data
    }

    static func x25519PublicKeyToSPKI(_ raw: Data) -> Data {
        let header: [UInt8] = [
            0x30, 0x2a,
            0x30, 0x05,
            0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x03, 0x21, 0x00
        ]
        return Data(header) + raw
    }

    static func x25519RawFromSPKI(_ der: Data) -> Data? {
        let bytes = [UInt8](der)
        let header: [UInt8] = [
            0x30, 0x2a,
            0x30, 0x05,
            0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x03, 0x21, 0x00
        ]
        if bytes.count >= header.count + 32 && Array(bytes.prefix(header.count)) == header {
            return Data(bytes.suffix(32))
        }
        if bytes.count >= 35 {
            for i in 0..<(bytes.count - 35) {
                if bytes[i] == 0x03, bytes[i + 1] == 0x21, bytes[i + 2] == 0x00 {
                    let start = i + 3
                    return Data(bytes[start..<(start + 32)])
                }
            }
        }
        return nil
    }
}

private extension AES.GCM.Nonce {
    var data: Data { withUnsafeBytes { Data($0) } }
}

private extension UInt64 {
    var bigEndianData: Data {
        var value = self.bigEndian
        return Data(bytes: &value, count: MemoryLayout<UInt64>.size)
    }
}
