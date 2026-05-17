import Foundation
import CryptoKit
import os.log

private let sdiLog = OSLog(subsystem: "com.bsh.sdi", category: "agent")

/// Unix domain socket IPC server.
///
/// ## Registration protocol (binary ECDH over Unix socket)
///
/// Shell → Agent (48 bytes sent atomically):
///   Bytes  0–15: `session_id`  — 16 cryptographically random bytes
///   Bytes 16–47: `shell_pub`   — ephemeral X25519 public key (32 bytes, raw)
///
/// Agent → Shell (32 bytes):
///   Bytes  0–31: `agent_pub`   — ephemeral X25519 public key (32 bytes, raw)
///
/// Both sides derive:
///   session_key = HKDF-SHA256(IKM=X25519_shared, salt=session_id, info="sdi-session-key", L=32)
/// Connection closes immediately after the exchange.
///
/// ## OSC 7777 relay (optional JSON message, sent on a *new* connection)
///
/// Shell → Agent:
///   { "op": "osc7777", "raw": "<escaped OSC sequence>" }
///
/// Agent → Shell (acknowledgement):
///   { "ok": true }   or   { "ok": false, "error": "<reason>" }
///
/// ## Session teardown (optional JSON message, sent on a *new* connection)
///
/// Shell → Agent:
///   { "op": "unregister", "session_id": "<32-char lowercase hex>" }
final class IPCServer {

    private let socketPath: String
    private let store: EphemeralStore
    private weak var menuBar: MenuBarController?

    /// In-memory session key map: session_id → 32-byte key Data.
    private var sessionKeys: [String: Data] = [:]
    private let keysLock = NSLock()

    /// Session registration timestamps for 8-hour expiry enforcement.
    private var sessionRegisteredAt: [String: Date] = [:]
    /// Failed decryption counts per session for rate limiting (10 failures/60 s).
    private var sessionFailures: [String: (count: Int, since: Date)] = [:]
    /// Next expected per-session counter for replay protection (RFC §3.5).
    private var sessionCounters: [String: UInt64] = [:]
    private let sessionsLock = NSLock()

    private let queue = DispatchQueue(label: "com.bsh.sdi.ipc", qos: .utility)

    init(store: EphemeralStore, menuBar: MenuBarController) {
        // Generate a per-run randomized socket path to prevent squatting (RFC §3.1).
        // Use FileManager.temporaryDirectory so the path stays inside the app's
        // sandbox container when App Sandbox is enabled (not the global /tmp).
        var rng = SystemRandomNumberGenerator()
        let suffix = String(format: "%016llx", rng.next())
        let tmpDir = FileManager.default.temporaryDirectory.path
        // No .sock suffix: the full path with suffix would exceed sockaddr_un.sun_path's
        // 104-byte limit on macOS, causing strlcpy to silently truncate it and creating
        // a mismatch between the advertised path and the actual socket file on disk.
        self.socketPath = "\(tmpDir)/sdi-agent-\(suffix)"
        self.store = store
        self.menuBar = menuBar
    }

    // MARK: - Start / Stop

    func start() {
        // RFC §3.1: Abort if a file already exists at our randomized socket path —
        // this should never happen with a fresh random name, but guards against collisions.
        guard !FileManager.default.fileExists(atPath: socketPath) else {
            NSLog("[SDIAgent] FATAL: socket path \(socketPath) already exists — aborting (squatting defense)")
            exit(1)
        }
        // Advertise path to child shells via a session-wide environment variable (RFC §3.1).
        setenv("SDI_SOCKET_PATH", socketPath, 1)
        // launchctl setenv works in non-sandboxed builds; silently ignored when sandboxed.
        let launchctlSet = Process()
        launchctlSet.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        launchctlSet.arguments = ["setenv", "SDI_SOCKET_PATH", socketPath]
        try? launchctlSet.run()
        // Fallback for sandboxed builds: write socket path to ~/.config/sdi/socket
        // so bsh can find it even when launchctl setenv is blocked.
        advertiseSocketPathToFile(socketPath)
        startPOSIX()
    }

    func stop() {
        try? FileManager.default.removeItem(atPath: socketPath)
        unsetenv("SDI_SOCKET_PATH")
        let launchctlUnset = Process()
        launchctlUnset.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        launchctlUnset.arguments = ["unsetenv", "SDI_SOCKET_PATH"]
        try? launchctlUnset.run()
        clearSocketPathFile()
    }

    // MARK: - Socket path advertisement (sandbox-safe fallback)

    /// Returns the real user home directory even inside an App Sandbox.
    /// `FileManager.default.homeDirectoryForCurrentUser` and `NSHomeDirectory()`
    /// both return the container home when sandboxed; `getpwuid` bypasses that.
    private static var realSocketPathFile: URL? {
        guard let pw = getpwuid(getuid()) else { return nil }
        let realHome = String(cString: pw.pointee.pw_dir)
        return URL(fileURLWithPath: realHome, isDirectory: true)
            .appendingPathComponent(".config/sdi/socket")
    }

    private func advertiseSocketPathToFile(_ path: String) {
        guard let file = Self.realSocketPathFile else { return }
        try? FileManager.default.createDirectory(
            at: file.deletingLastPathComponent(),
            withIntermediateDirectories: true)
        try? path.write(to: file, atomically: true, encoding: .utf8)
    }

    private func clearSocketPathFile() {
        guard let file = Self.realSocketPathFile else { return }
        try? FileManager.default.removeItem(at: file)
    }

    // MARK: - POSIX Unix Domain Socket

    /// Uses POSIX directly since NWListener doesn't support AF_UNIX cleanly on all macOS versions.
    private func startPOSIX() {
        queue.async { [weak self] in
            self?.runAcceptLoop()
        }
    }

    private func runAcceptLoop() {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            NSLog("[SDIAgent] Failed to create socket: \(errno)")
            return
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let sunPathSize = MemoryLayout.size(ofValue: addr.sun_path)
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            socketPath.withCString { cstr in
                _ = strlcpy(UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self),
                            cstr, sunPathSize)
            }
        }

        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else {
            NSLog("[SDIAgent] bind failed: \(errno)")
            close(fd)
            return
        }

        // chmod 600 — owner read/write only
        chmod(socketPath, 0o600)

        guard listen(fd, 10) == 0 else {
            NSLog("[SDIAgent] listen failed: \(errno)")
            close(fd)
            return
        }

        NSLog("[SDIAgent] Listening on \(socketPath)")

        while true {
            let clientFD = accept(fd, nil, nil)
            guard clientFD >= 0 else { continue }
            // Dispatch each client to a global concurrent queue, NOT the serial `queue`.
            // runAcceptLoop blocks on accept() as a work item on the serial queue;
            // dispatching handleClient back to the same queue would deadlock since the
            // serial queue can only run one item at a time.
            DispatchQueue.global(qos: .utility).async { [weak self] in
                self?.handleClient(fd: clientFD)
            }
        }
    }

    // MARK: - Client handler

    /// Dispatches an accepted connection to the binary ECDH handler or the JSON message handler
    /// depending on the first byte received.
    private func handleClient(fd: Int32) {
        defer { close(fd) }

        // Peek at the first byte without consuming it.
        var firstByte: UInt8 = 0
        let peekResult = recv(fd, &firstByte, 1, MSG_PEEK)
        guard peekResult == 1 else {
            os_log("handleClient: peek returned %{public}d (errno=%{public}d) — closing", log: sdiLog, type: .info, peekResult, errno)
            return
        }

        if firstByte == UInt8(ascii: "{") {
            os_log("Accepted JSON-mode connection", log: sdiLog, type: .info)
            handleJSONSession(fd: fd)
        } else {
            os_log("Accepted binary-handshake connection (first byte=0x%{public}02x)", log: sdiLog, type: .info, firstByte)
            handleBinaryHandshake(fd: fd)
        }
    }

    // MARK: - Binary ECDH registration

    /// Reads 48 bytes (session_id[16] || shell_pub[32]), performs X25519 key agreement,
    /// writes back agent_pub[32], derives the session key via HKDF-SHA256, and stores it.
    private func handleBinaryHandshake(fd: Int32) {
        var packet = Data(count: 48)
        var totalRead = 0
        while totalRead < 48 {
            let n = packet.withUnsafeMutableBytes { ptr in
                read(fd, ptr.baseAddress!.advanced(by: totalRead), 48 - totalRead)
            }
            if n <= 0 {
                NSLog("[SDIAgent] Binary handshake: short read (%d/48 bytes)", totalRead)
                return
            }
            totalRead += n
        }

        let sessionIDData = packet[0..<16]
        let shellPubData  = packet[16..<48]

        // Generate agent's ephemeral X25519 keypair.
        let agentPrivKey = Curve25519.KeyAgreement.PrivateKey()

        // Send 32-byte agent public key back to the shell.
        let agentPubBytes = agentPrivKey.publicKey.rawRepresentation
        var written = 0
        while written < 32 {
            let n = agentPubBytes.withUnsafeBytes { ptr in
                write(fd, ptr.baseAddress!.advanced(by: written), 32 - written)
            }
            if n <= 0 { return }
            written += n
        }

        // ECDH + HKDF-SHA256 to derive the shared session key.
        // sessionIDHex is declared here so it is visible after the do-catch.
        var sessionIDHex: String = ""
        do {
            let shellPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: shellPubData)
            let sharedSecret = try agentPrivKey.sharedSecretFromKeyAgreement(with: shellPub)

            let sessionKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: sessionIDData,
                sharedInfo: Data("sdi-session-key".utf8),
                outputByteCount: 32
            )

            let sid = sessionIDData.map { String(format: "%02x", $0) }.joined()
            let sessionKeyData = sessionKey.withUnsafeBytes { Data($0) }

            keysLock.lock()
            sessionKeys[sid] = sessionKeyData
            keysLock.unlock()

            // Record registration time for session expiry (RFC §3.1).
            // Reset counter for the new session (RFC §3.5).
            sessionsLock.lock()
            sessionRegisteredAt[sid] = Date()
            sessionCounters[sid] = 0
            sessionsLock.unlock()

            sessionIDHex = sid
            os_log("ECDH handshake complete for session %{public}@", log: sdiLog, type: .info, sid)
        } catch {
            os_log("ECDH key agreement failed: %{public}@", log: sdiLog, type: .error, error.localizedDescription)
            return
        }

        // Enter the OSC delivery loop — bsh keeps the connection open for the
        // lifetime of the shell session.  handleBinaryHandshake returns only
        // after the shell disconnects or sends the UNREGISTER opcode (0x03).
        handleDeliverLoop(fd: fd, sessionIDHex: sessionIDHex)
    }

    // MARK: - Binary OSC deliver loop

    /// Reads successive OSC packets from the bsh connection after ECDH.
    ///
    /// Protocol (per RFC §3.6 Option B):
    /// - opcode 0x02 (OSC_DELIVER): bsh sends LE32(len) + OSC bytes;
    ///   SDIAgent processes it and writes 0x01 (ok) or 0x00 (fail).
    /// - opcode 0x03 (UNREGISTER): graceful shell exit — loop ends.
    /// - EOF / unknown opcode: treat as abrupt disconnect — loop ends.
    ///
    /// The session is invalidated when the loop exits (shell is gone).
    private func handleDeliverLoop(fd: Int32, sessionIDHex: String) {
        defer {
            // Only revoke the crypto key — stored credentials live until their TTL.
            // (Calling invalidateSession here would wipe credentials immediately on
            // shell exit, making bsh -c / register-user.ts credentials disappear
            // before the application can read them.)
            revokeSessionKeys(sessionIDHex)
            os_log("Session %{public}@ disconnected — crypto keys revoked, credentials retained until TTL",
                   log: sdiLog, type: .info, sessionIDHex)
        }

        while true {
            // Read 1-byte opcode.
            var opcode: UInt8 = 0
            let nr = withUnsafeMutablePointer(to: &opcode) { read(fd, $0, 1) }
            if nr <= 0 { break }   // EOF = shell exited

            switch opcode {

            case 0x02:   // OSC_DELIVER
                // Read 4-byte little-endian length.
                var lenBuf = [UInt8](repeating: 0, count: 4)
                var totalRead = 0
                while totalRead < 4 {
                    let r = read(fd, &lenBuf[totalRead], 4 - totalRead)
                    if r <= 0 { return }
                    totalRead += r
                }
                let length = UInt32(lenBuf[0])
                             | (UInt32(lenBuf[1]) << 8)
                             | (UInt32(lenBuf[2]) << 16)
                             | (UInt32(lenBuf[3]) << 24)

                guard length > 0, length <= 4 * 1024 * 1024 else {
                    os_log("handleDeliverLoop: invalid OSC length %u — rejecting",
                           log: sdiLog, type: .error, length)
                    var ack: UInt8 = 0x00
                    write(fd, &ack, 1)
                    continue
                }

                // Read OSC bytes.
                var oscData = Data(count: Int(length))
                var totalOSC = 0
                while totalOSC < Int(length) {
                    let r = oscData.withUnsafeMutableBytes { ptr in
                        read(fd, ptr.baseAddress!.advanced(by: totalOSC),
                             Int(length) - totalOSC)
                    }
                    if r <= 0 { return }
                    totalOSC += r
                }

                var ack: UInt8
                if let oscString = String(data: oscData, encoding: .utf8) {
                    ack = processOSCString(oscString) ? 0x01 : 0x00
                } else {
                    os_log("handleDeliverLoop: OSC payload is not valid UTF-8 — rejecting",
                           log: sdiLog, type: .error)
                    ack = 0x00
                }
                write(fd, &ack, 1)

            case 0x03:   // UNREGISTER — graceful shell exit
                os_log("handleDeliverLoop: UNREGISTER for session %{public}@",
                       log: sdiLog, type: .info, sessionIDHex)
                return

            default:
                os_log("handleDeliverLoop: unknown opcode 0x%02x — closing",
                       log: sdiLog, type: .error, opcode)
                return
            }
        }
    }

    // MARK: - JSON message session

    /// Reads newline-delimited JSON messages (osc7777 relay, unregister) from a connection.
    private func handleJSONSession(fd: Int32) {
        var buffer = Data()
        let chunkSize = 4096
        var chunk = [UInt8](repeating: 0, count: chunkSize)

        while true {
            let n = read(fd, &chunk, chunkSize)
            guard n > 0 else { break }
            buffer.append(contentsOf: chunk[0..<n])

            while let newlineIdx = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                let lineData = buffer[buffer.startIndex...newlineIdx]
                buffer = buffer[buffer.index(after: newlineIdx)...]
                handleMessage(Data(lineData), clientFD: fd)
            }
        }
    }

    /// Process one JSON message.
    private func handleMessage(_ data: Data, clientFD: Int32) {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let op = json["op"] as? String else {
            sendResponse(["ok": false, "error": "invalid message"], fd: clientFD)
            return
        }

        os_log("handleMessage: op=%{public}@", log: sdiLog, type: .info, op)
        switch op {
        case "register":
            sendResponse(["ok": false, "error": "binary ECDH handshake required; JSON registration not supported"], fd: clientFD)

        case "osc7777":
            handleOSC7777(json, fd: clientFD)

        case "unregister":
            if let sid = json["session_id"] as? String {
                keysLock.lock()
                sessionKeys.removeValue(forKey: sid)
                keysLock.unlock()
                sessionsLock.lock()
                sessionRegisteredAt.removeValue(forKey: sid)
                sessionFailures.removeValue(forKey: sid)
                sessionCounters.removeValue(forKey: sid)
                sessionsLock.unlock()
                store.removeSession(sid)
                NSLog("[SDIAgent] Explicit unregister: \(sid)")
            }
            sendResponse(["ok": true], fd: clientFD)

        default:
            sendResponse(["ok": false, "error": "unknown op"], fd: clientFD)
        }
    }

    private func handleOSC7777(_ json: [String: Any], fd: Int32) {
        guard let raw = json["raw"] as? String else {
            os_log("handleOSC7777: missing 'raw' field — dropping", log: sdiLog, type: .error)
            sendResponse(["ok": false, "error": "missing raw field"], fd: fd)
            return
        }
        os_log("handleOSC7777: received raw payload (%{public}d chars)", log: sdiLog, type: .info, raw.count)
        processOSCString(raw)
        sendResponse(["ok": true], fd: fd)
    }

    // MARK: - OSC 7777 processing

    /// Called either from the binary deliver loop or from the JSON IPC relay.
    /// Returns `true` if at least one packet was successfully decrypted and stored.
    @discardableResult
    func processOSCString(_ raw: String) -> Bool {
        var anySuccess = false
        let packets = OSC7777Parser.scan(raw)
        os_log("processOSCString: parsed %{public}d packet(s) from %{public}d-char input", log: sdiLog, type: .info, packets.count, raw.count)
        if packets.isEmpty {
            let prefix = String(raw.prefix(80))
            let hexPreview = prefix.unicodeScalars.map { scalar -> String in
                let v = scalar.value
                if v >= 0x20 && v < 0x7f && v != UInt32(UInt8(ascii: "\\")) {
                    return String(scalar)
                } else {
                    return String(format: "\\x%02x", v)
                }
            }.joined()
            os_log("processOSCString: no OSC 7777 packets matched. Input preview: %{public}@", log: sdiLog, type: .error, hexPreview)
        }
        for packet in packets {
            keysLock.lock()
            let key = sessionKeys[packet.sessionID]
            keysLock.unlock()

            guard let sessionKey = key else {
                os_log("Unknown session_id %{public}@ — dropping packet.", log: sdiLog, type: .error, packet.sessionID)
                continue
            }

            // Session expiry check — 8-hour maximum lifetime (RFC §3.1).
            sessionsLock.lock()
            let registeredAt = sessionRegisteredAt[packet.sessionID]
            sessionsLock.unlock()
            if let t = registeredAt, Date().timeIntervalSince(t) > 8 * 3600 {
                os_log("Session %{public}@ expired — invalidating and dropping.", log: sdiLog, type: .error, packet.sessionID)
                invalidateSession(packet.sessionID)
                continue
            }

            // Validate and advance the per-session monotonic counter (RFC §3.5).
            let counterValue = packet.counter.withUnsafeBytes { bytes -> UInt64 in
                var v: UInt64 = 0
                for i in 0..<8 { v = (v << 8) | UInt64(bytes[i]) }
                return v
            }
            sessionsLock.lock()
            let expectedCounter = sessionCounters[packet.sessionID] ?? 0
            sessionsLock.unlock()
            guard counterValue >= expectedCounter else {
                os_log("Counter replay: got %llu, expected >= %llu for session %{public}@ — dropping.",
                       log: sdiLog, type: .error, counterValue, expectedCounter, packet.sessionID)
                continue
            }

            // Reconstruct AAD matching sdi.c's LE32-prefixed format (RFC §3.4).
            let aad = Self.buildAAD(counter: packet.counter, type: packet.type, context: packet.context)

            do {
                let payload = try CryptoEngine.decryptPayload(
                    sessionKey: sessionKey,
                    nonce: packet.nonce,
                    ciphertext: packet.ciphertext,
                    additionalData: aad
                )
                sessionsLock.lock()
                sessionFailures.removeValue(forKey: packet.sessionID)
                sessionCounters[packet.sessionID] = counterValue + 1
                sessionsLock.unlock()
                store.insert(payload: payload, sessionID: packet.sessionID)
                anySuccess = true
                os_log("Stored payload for context: %{public}@", log: sdiLog, type: .info, payload.context)
            } catch {
                // Rate limiting: track failures per session (RFC §3.2).
                sessionsLock.lock()
                var rec = sessionFailures[packet.sessionID] ?? (count: 0, since: Date())
                if Date().timeIntervalSince(rec.since) > 60 { rec = (count: 0, since: Date()) }
                rec.count += 1
                sessionFailures[packet.sessionID] = rec
                let tooMany = rec.count >= 10
                sessionsLock.unlock()
                os_log("Decryption failed for session %{public}@: %{public}@ — dropping.",
                       log: sdiLog, type: .error, packet.sessionID, String(describing: error))
                if tooMany {
                    os_log("Rate limit: 10+ failures for session %{public}@ — invalidating.",
                           log: sdiLog, type: .error, packet.sessionID)
                    invalidateSession(packet.sessionID)
                }
            }
        }
        return anySuccess
    }

    // MARK: - Helpers

    /// Build the Additional Authenticated Data matching sdi.c's LE32-prefixed format (RFC §3.4).
    /// Format: LE32(8) || counter_bytes(8) || LE32(len) || type_bytes || LE32(len) || ctx_bytes
    private static func buildAAD(counter: Data, type typeStr: String, context: String) -> Data {
        var aad = Data()
        func appendLE32(_ n: UInt32) {
            var v = n.littleEndian
            withUnsafeBytes(of: &v) { aad.append(contentsOf: $0) }
        }
        let typeBytes = Data(typeStr.utf8)
        let ctxBytes  = Data(context.utf8)
        appendLE32(8)
        aad.append(counter)
        appendLE32(UInt32(typeBytes.count))
        aad.append(typeBytes)
        appendLE32(UInt32(ctxBytes.count))
        aad.append(ctxBytes)
        return aad
    }

    /// Revokes only the crypto key and counters for a session (called on shell disconnect).
    /// Stored credentials are retained in EphemeralStore until their TTL expires.
    private func revokeSessionKeys(_ sid: String) {
        keysLock.lock()
        sessionKeys.removeValue(forKey: sid)
        keysLock.unlock()
        sessionsLock.lock()
        sessionRegisteredAt.removeValue(forKey: sid)
        sessionFailures.removeValue(forKey: sid)
        sessionCounters.removeValue(forKey: sid)
        sessionsLock.unlock()
    }

    /// Removes all state for a session including stored credentials
    /// (triggered by 8-hour expiry, rate-limit, or explicit Clear All).
    private func invalidateSession(_ sid: String) {
        revokeSessionKeys(sid)
        store.removeSession(sid)
    }

    private func sendResponse(_ dict: [String: Any], fd: Int32) {
        guard var data = try? JSONSerialization.data(withJSONObject: dict) else { return }
        data.append(UInt8(ascii: "\n"))
        _ = data.withUnsafeBytes { write(fd, $0.baseAddress!, $0.count) }
    }
}
