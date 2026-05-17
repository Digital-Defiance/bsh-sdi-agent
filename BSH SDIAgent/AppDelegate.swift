import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var menuBarController: MenuBarController?
    private var ipcServer: IPCServer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory) // no Dock icon

        let store = EphemeralStore()
        menuBarController = MenuBarController(store: store)
        ipcServer = IPCServer(store: store, menuBar: menuBarController!)
        ipcServer?.start()
    }

    func applicationWillTerminate(_ notification: Notification) {
        ipcServer?.stop()
    }
}
