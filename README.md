# KREO iOS Client

SwiftUI client for the KREO relay chat protocol. The app connects to a relay via WebSocket, performs a PGP login challenge, derives a shared group key, and exchanges encrypted chat messages.

## Structure
- `KREOApp.swift`: app entry point.
- `ContentView.swift`: SwiftUI UI for tabs, forms, chat, and settings.
- `ChatViewModel.swift`: state, networking, crypto, relay discovery, and message handling.
- `KeychainManager.swift`: Keychain storage for PGP private keys.

## Functions and Types

### KREOApp.swift
- `KREOApp`: App entry that loads `ContentView` in the main window.

### ContentView.swift (Views)
- `ContentView`: Top-level tab bar; manages chat unread badge and relay discovery.
- `ChatTabView`: Chat screen; shows history and composer when connected/authed/joined.
- `ConnectionTabView`: Connection form + relay discovery + challenge + status.
- `LogTabView`: Log viewer with show/hide toggle.
- `PGPKeyTabView`: Import/clear private key; shows public key + fingerprint.
- `ConnectionSection`: Inputs for server, username, session, passphrase, nickname, key ID.
- `RegistrationSection`: Optional registration public key editor.
- `StatusSection`: Read-only connection/auth/join/epoch status.
- `ChallengeSection`: Shows PGP challenge, decrypts, and submits response.
- `ConnectionActions`: Connect/reconnect and disconnect buttons.
- `LogToggle`: Shows/hides logs.
- `LogView` / `LogScrollView`: Scrollable, auto-scrolling log list.
- `MessageComposer`: Message input + send button.
- `StatusBanner` / `StatusPill`: Compact connection status indicators.
- `ChatHistoryView`: Renders chat bubbles with speaker labels and auto-scroll.
- `ChatBubble`: Styled chat message bubble.
- `ChatEntry`: Parses stored chat line into sender label/text.
- `SettingsTabView`: Relay picker, chat toggles, and debug commands.
- `RelayDiscoverySection`: Relay list with health status and “Use” actions.
- `RelayStatusDot`: Color dot for relay health.
- `keyboardDismissButton` / `hideKeyboard`: Adds a keyboard toolbar “Done” button.

### KeychainManager.swift
- `saveString`: Stores a string in the Keychain.
- `readString`: Reads a stored string from the Keychain.
- `delete`: Removes a Keychain entry.

### ChatViewModel.swift

Public actions
- `connect`: Normalize inputs, reset state, open WebSocket, and start listening.
- `disconnect`: Close socket, clear state, and log disconnect.
- `discoverRelays`: Fetch the relay list.
- `refreshRelayStatuses`: Check health endpoints for known relays.
- `useRelay`: Select a relay URL.
- `logPeers`: Log peers active in the current epoch.
- `logSessionInfo`: Log session ID and epoch.
- `logRelayInfo`: Log connected and entry relay.
- `logSafetyCode`: Log the derived safety code.
- `manualRekey`: Force a rekey.
- `generateSessionId`: Generate a random session ID.
- `generatePassphrase`: Generate a random passphrase.
- `sendLoginChallengeResponse`: Send decrypted PGP challenge response.
- `importPrivateKey`: Save a PGP private key to Keychain.
- `clearPrivateKey`: Remove PGP private key from Keychain.
- `decryptPendingChallenge`: Decrypt pending armored challenge.
- `sendChatMessage`: Send a message or handle a slash command.
- `markChatRead`: Clear unread badge count.

WebSocket + message handling
- `listen`: Receive messages from the WebSocket and dispatch handlers.
- `handleMessageText`: Parse JSON text into a dictionary.
- `handleMessage`: Dispatch on message type (login, join, announce, ciphertext).
- `handleLoginChallenge`: Store the PGP challenge for decryption.
- `sendLoginInit`: Start login with username + key ID.
- `handleAnnounce`: Track peer key material and trigger rekey if needed.
- `handleCiphertext`: Decrypt and display incoming messages.
- `safeSend`: Serialize and send a JSON frame over the socket.

Key management + crypto
- `startRekey`: Reset epoch/key material and broadcast a new announce.
- `sendAnnounce`: Broadcast current identity and epoch.
- `deriveGroupKey`: Derive the symmetric group key and safety code.
- `hkdfSHA256`: HKDF implementation used by `deriveGroupKey`.
- `sendEncrypted`: Encrypt a message with AES-GCM and send.
- `buildAad`: Build AAD for AES-GCM.
- `senderIdFromPublic`: Derive sender ID from public key.
- `isSeen`: Check if a ciphertext was already processed.
- `markSeen`: Track processed message IDs or counters.

Logging and validation
- `appendLog`: Add a line to the bounded log buffer.
- `appendChat`: Add a line to the bounded chat buffer and manage unread count.
- `handleChatCommand`: Handle slash commands (e.g., `/relay`).
- `sanitizeNick`: Limit nickname to 32 ASCII chars.
- `normalizeServer`: Ensure a ws:// or wss:// URL.

PGP status helpers
- `refreshPgpKeyStatus`: Refresh PGP status flags from Keychain.
- `updatePgpFingerprint`: Compute fingerprint for the private key.
- `updatePgpPublicKey`: Export the public key armor.

Relay discovery + health
- `fetchRelayList`: Download and parse the relay list JSON.
- `relaySort`: Sort relays by base domain/host.
- `relayHost`: Extract host from relay URL.
- `baseDomain`: Get base domain for sorting.
- `checkRelayHealth`: Query relay health endpoints in parallel.
- `checkHealth`: Fetch `/health` for a single relay.
- `toHttp`: Convert ws/wss to http/https for health checks.

Types and helpers
- `RelayHealth`: Relay status enum.
- `RelayListResponse`: Relay list JSON structure.
- `HealthResponse`: Health JSON structure.
- `Identity.generate`: Create Curve25519 keypair and sender ID.
- `Peer`: Peer info container.
- `Data` extensions: byte concat, random bytes, hex, and X25519 SPKI helpers.
- `AES.GCM.Nonce.data`: Data view of a nonce.
- `UInt64.bigEndianData`: Big-endian byte representation.

