import SwiftUI

@main
struct SDIAgentApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        // No windows — pure menu bar agent
        Settings { EmptyView() }
    }
}
