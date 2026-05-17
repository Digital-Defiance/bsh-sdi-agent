import AppKit

/// Manages the macOS menu bar status item.
///
/// Displays a lock icon. When active credentials are present, shows a badge
/// and a menu listing each context with its TTL countdown.
final class MenuBarController {

    private var statusItem: NSStatusItem?
    private let store: EphemeralStore
    private var refreshTimer: Timer?

    init(store: EphemeralStore) {
        self.store = store
        setup()
        store.onChange = { [weak self] in
            self?.refresh()
        }
        startRefreshTimer()
    }

    // MARK: - Setup

    private func setup() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        updateIcon(active: false)
        buildMenu()
    }

    // MARK: - Refresh

    private func startRefreshTimer() {
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    @objc private func refresh() {
        let entries = store.activeEntries()
        updateIcon(active: !entries.isEmpty)
        buildMenu(entries: entries)
    }

    // MARK: - Icon

    private func updateIcon(active: Bool) {
        guard let button = statusItem?.button else { return }
        let symbolName = active ? "lock.open.fill" : "lock.fill"
        let image = NSImage(systemSymbolName: symbolName, accessibilityDescription: "SDI Agent")
        image?.isTemplate = true
        button.image = image
        button.toolTip = active ? "BSH SDI Agent — credentials active" : "BSH SDI Agent — idle"
    }

    // MARK: - Menu

    private func buildMenu(entries: [EphemeralStore.Entry] = []) {
        let menu = NSMenu()

        if entries.isEmpty {
            let idle = NSMenuItem(title: "No active credentials", action: nil, keyEquivalent: "")
            idle.isEnabled = false
            menu.addItem(idle)
        } else {
            let header = NSMenuItem(title: "Active Credentials", action: nil, keyEquivalent: "")
            header.isEnabled = false
            menu.addItem(header)
            menu.addItem(.separator())

            let now = Date()
            for entry in entries.sorted(by: { $0.payload.context < $1.payload.context }) {
                let remaining = max(0, entry.expiresAt.timeIntervalSince(now))
                let mins = Int(remaining) / 60
                let secs = Int(remaining) % 60
                let ttlLabel = mins > 0 ? "\(mins)m \(secs)s" : "\(secs)s"
                let label = "\(entry.payload.context)  [\(ttlLabel)]"
                let item = NSMenuItem(title: label, action: nil, keyEquivalent: "")

                let submenu = NSMenu()

                // Type header
                let typeItem = NSMenuItem(title: "Type: \(entry.payload.type.rawValue)", action: nil, keyEquivalent: "")
                typeItem.isEnabled = false
                submenu.addItem(typeItem)
                submenu.addItem(.separator())

                // Copy context URL
                submenu.addItem(makeItem("Copy URL", value: entry.payload.context))

                // ephemeral-auth fields
                let d = entry.payload.data
                if let v = d.username { submenu.addItem(makeItem("Copy Username  (\(v))", value: v)) }
                if let v = d.password { submenu.addItem(makeItem("Copy Password  (••••••••)", value: v)) }
                if let v = d.email    { submenu.addItem(makeItem("Copy Email  (\(v))", value: v)) }

                // db-connection fields
                if let v = d.user    { submenu.addItem(makeItem("Copy User  (\(v))", value: v)) }
                if let v = d.pass    { submenu.addItem(makeItem("Copy Pass  (••••••••)", value: v)) }
                if let v = d.host    { submenu.addItem(makeItem("Copy Host  (\(v))", value: v)) }
                if let v = d.engine  { submenu.addItem(makeItem("Copy Engine  (\(v))", value: v)) }
                if let p = d.port    { submenu.addItem(makeItem("Copy Port  (\(p))", value: String(p))) }

                item.submenu = submenu
                menu.addItem(item)
            }

            menu.addItem(.separator())
            let clear = NSMenuItem(title: "Clear All", action: #selector(clearAll), keyEquivalent: "")
            clear.target = self
            menu.addItem(clear)
        }

        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit BSH SDI Agent", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))

        statusItem?.menu = menu
    }

    // MARK: - Helpers

    private func makeItem(_ title: String, value: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: #selector(copyField(_:)), keyEquivalent: "")
        item.target = self
        item.representedObject = value
        return item
    }

    // MARK: - Actions

    @objc private func copyField(_ sender: NSMenuItem) {
        guard let value = sender.representedObject as? String else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    @objc private func clearAll() {
        // Remove all active entries by clearing each session
        let entries = store.activeEntries()
        let sessions = Set(entries.map { $0.sessionID })
        sessions.forEach { store.removeSession($0) }
        refresh()
    }
}
