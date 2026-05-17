import Foundation

/// Thread-safe in-memory store for decrypted SDI payloads with TTL sweeping.
final class EphemeralStore {

    // MARK: - Internal types

    struct Entry {
        let payload: SDIPayload
        let expiresAt: Date
        let sessionID: String
    }

    // MARK: - State

    private let lock = NSLock()
    /// Keyed by context string (e.g. "http://localhost:3005")
    private var entries: [String: Entry] = [:]
    private var sweepTimer: Timer?

    /// Notified when the store contents change (for menu bar refresh).
    var onChange: (() -> Void)?

    // MARK: - Lifecycle

    init() { }

    deinit {
        sweepTimer?.invalidate()
    }

    // MARK: - Public API

    /// Store a newly decrypted payload, overwriting any prior entry for the same context.
    func insert(payload: SDIPayload, sessionID: String) {
        let ttl = payload.ttl > 0 ? payload.ttl : 300
        let entry = Entry(
            payload: payload,
            expiresAt: Date().addingTimeInterval(ttl),
            sessionID: sessionID
        )
        lock.lock()
        entries[payload.context] = entry
        lock.unlock()
        notifyChange()
        rescheduleSweeper()
    }

    /// Remove all entries associated with a terminal session (called on disconnect).
    func removeSession(_ sessionID: String) {
        lock.lock()
        entries = entries.filter { $0.value.sessionID != sessionID }
        lock.unlock()
        notifyChange()
        rescheduleSweeper()
    }

    /// Snapshot of all currently active entries (not yet expired).
    func activeEntries() -> [Entry] {
        lock.lock()
        defer { lock.unlock() }
        return Array(entries.values)
    }

    // MARK: - TTL Sweeper

    /// Schedule a one-shot timer to fire the instant the nearest credential expires.
    /// Safe to call from any thread; timer scheduling is dispatched to the main run loop.
    private func rescheduleSweeper() {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.sweepTimer?.invalidate()
            self.lock.lock()
            let next = self.entries.values.map(\.expiresAt).min()
            self.lock.unlock()
            guard let next else { return }  // no entries — no timer needed
            let delay = max(0, next.timeIntervalSinceNow)
            self.sweepTimer = Timer.scheduledTimer(withTimeInterval: delay, repeats: false) { [weak self] _ in
                self?.sweep()
            }
        }
    }

    private func sweep() {
        let now = Date()
        var changed = false
        lock.lock()
        let before = entries.count
        entries = entries.filter { $0.value.expiresAt > now }
        changed = entries.count != before
        lock.unlock()
        if changed { notifyChange() }
        rescheduleSweeper()  // schedule for the next nearest expiry
    }

    private func notifyChange() {
        DispatchQueue.main.async { [weak self] in
            self?.onChange?()
        }
    }
}
