// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension

#if SWIFT_PACKAGE
import WireGuardKitGo
import WireGuardKitC
#endif

public enum WireGuardAdapterError: Error {
    /// Failure to locate tunnel file descriptor.
    case cannotLocateTunnelFileDescriptor

    /// Failure to perform an operation in such state.
    case invalidState

    /// Failure to resolve endpoints.
    case dnsResolution([DNSResolutionError])

    /// Failure to set network settings.
    case setNetworkSettings(Error)

    /// Failure to start WireGuard backend.
    case startWireGuardBackend(Int32)
}

/// Enum representing internal state of the `WireGuardAdapter`
private enum State {
    /// The tunnel is stopped
    case stopped

    /// The tunnel is up and running
    case started(_ handle: Int32, _ settingsGenerator: PacketTunnelSettingsGenerator)

    /// The tunnel is temporarily shutdown due to device going offline
    case temporaryShutdown(_ settingsGenerator: PacketTunnelSettingsGenerator)

    /// The settings generator of the running configuration, or `nil` when stopped.
    var settingsGenerator: PacketTunnelSettingsGenerator? {
        switch self {
        case .started(_, let settingsGenerator), .temporaryShutdown(let settingsGenerator):
            return settingsGenerator
        case .stopped:
            return nil
        }
    }
}

public class WireGuardAdapter {
    public typealias LogHandler = (WireGuardLogLevel, String) -> Void

    /// Network routes monitor.
    private var networkMonitor: NWPathMonitor?

    /// The path update waiting to be handled. See `schedulePathUpdate(_:)`.
    private var pendingPathUpdate: DispatchWorkItem?

    /// How long a path update waits for a newer one before it is handled.
    private static let pathUpdateDebounceInterval: DispatchTimeInterval = .milliseconds(100)

    /// Packet tunnel provider.
    private weak var packetTunnelProvider: NEPacketTunnelProvider?

    /// Log handler closure.
    private let logHandler: LogHandler

    /// Private queue used to synchronize access to `WireGuardAdapter` members.
    private let workQueue = DispatchQueue(label: "WireGuardAdapterWorkQueue")

    /// Adapter state.
    private var state: State = .stopped

    /// Tunnel device file descriptor.
    private var tunnelFileDescriptor: Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }

    /// Returns a WireGuard version.
    class var backendVersion: String {
        guard let ver = wgVersion() else { return "unknown" }
        let str = String(cString: ver)
        free(UnsafeMutableRawPointer(mutating: ver))
        return str
    }

    /// Returns the tunnel device interface name, or nil on error.
    /// - Returns: String.
    public var interfaceName: String? {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else { return nil }

        var buffer = [UInt8](repeating: 0, count: Int(IFNAMSIZ))

        return buffer.withUnsafeMutableBufferPointer { mutableBufferPointer in
            guard let baseAddress = mutableBufferPointer.baseAddress else { return nil }

            var ifnameSize = socklen_t(IFNAMSIZ)
            let result = getsockopt(
                tunnelFileDescriptor,
                2 /* SYSPROTO_CONTROL */,
                2 /* UTUN_OPT_IFNAME */,
                baseAddress,
                &ifnameSize)

            if result == 0 {
                return String(cString: baseAddress)
            } else {
                return nil
            }
        }
    }

    // MARK: - Initialization

    /// Designated initializer.
    /// - Parameter packetTunnelProvider: an instance of `NEPacketTunnelProvider`. Internally stored
    ///   as a weak reference.
    /// - Parameter logHandler: a log handler closure.
    public init(with packetTunnelProvider: NEPacketTunnelProvider, logHandler: @escaping LogHandler) {
        self.packetTunnelProvider = packetTunnelProvider
        self.logHandler = logHandler

        setupLogHandler()
    }

    deinit {
        // Force remove logger to make sure that no further calls to the instance of this class
        // can happen after deallocation.
        wgSetLogger(nil, nil)

        // Cancel network monitor
        networkMonitor?.cancel()
        pendingPathUpdate?.cancel()

        // Shutdown the tunnel
        if case .started(let handle, _) = self.state {
            wgTurnOff(handle)
        }
    }

    // MARK: - Public methods

    /// Returns a runtime configuration from WireGuard.
    /// - Parameter completionHandler: completion handler.
    public func getRuntimeConfiguration(completionHandler: @escaping (String?) -> Void) {
        workQueue.async {
            guard case .started(let handle, _) = self.state else {
                completionHandler(nil)
                return
            }

            if let settings = wgGetConfig(handle) {
                completionHandler(String(cString: settings))
                free(settings)
            } else {
                completionHandler(nil)
            }
        }
    }

    /// Start the tunnel tunnel.
    /// - Parameters:
    ///   - tunnelConfiguration: tunnel configuration.
    ///   - completionHandler: completion handler.
    public func start(tunnelConfiguration: TunnelConfiguration, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            guard case .stopped = self.state else {
                completionHandler(.invalidState)
                return
            }

            let networkMonitor = NWPathMonitor()
            networkMonitor.pathUpdateHandler = { [weak self] path in
                self?.schedulePathUpdate(path)
            }
            networkMonitor.start(queue: self.workQueue)

            do {
                let settingsGenerator = try self.makeSettingsGenerator(with: tunnelConfiguration)
                try self.setNetworkSettings(settingsGenerator.generateNetworkSettings())

                let (wgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                self.logEndpointResolutionResults(resolutionResults)

                self.state = .started(
                    try self.startWireGuardBackend(wgConfig: wgConfig),
                    settingsGenerator
                )
                self.networkMonitor = networkMonitor
                completionHandler(nil)
            } catch let error as WireGuardAdapterError {
                networkMonitor.cancel()
                completionHandler(error)
            } catch {
                fatalError()
            }
        }
    }

    /// Stop the tunnel.
    /// - Parameter completionHandler: completion handler.
    public func stop(completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            switch self.state {
            case .started(let handle, _):
                wgTurnOff(handle)

            case .temporaryShutdown:
                break

            case .stopped:
                completionHandler(.invalidState)
                return
            }

            self.networkMonitor?.cancel()
            self.networkMonitor = nil
            self.pendingPathUpdate?.cancel()
            self.pendingPathUpdate = nil

            self.state = .stopped

            completionHandler(nil)
        }
    }

    /// Update runtime configuration.
    /// - Parameters:
    ///   - tunnelConfiguration: tunnel configuration.
    ///   - completionHandler: completion handler.
    public func update(tunnelConfiguration: TunnelConfiguration, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            if case .stopped = self.state {
                completionHandler(.invalidState)
                return
            }

            // Tell the system that the tunnel is going to reconnect using new WireGuard
            // configuration.
            // This will broadcast the `NEVPNStatusDidChange` notification to the GUI process.
            self.packetTunnelProvider?.reasserting = true
            defer {
                self.packetTunnelProvider?.reasserting = false
            }

            do {
                let settingsGenerator = try self.makeSettingsGenerator(with: tunnelConfiguration)
                try self.setNetworkSettings(settingsGenerator.generateNetworkSettings())

                switch self.state {
                case .started(let handle, _):
                    let (wgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                    self.logEndpointResolutionResults(resolutionResults)

                    wgSetConfig(handle, wgConfig)
                    #if os(iOS)
                    wgDisableSomeRoamingForBrokenMobileSemantics(handle)
                    #endif

                    self.state = .started(handle, settingsGenerator)

                case .temporaryShutdown:
                    self.state = .temporaryShutdown(settingsGenerator)

                case .stopped:
                    fatalError()
                }

                completionHandler(nil)
            } catch let error as WireGuardAdapterError {
                completionHandler(error)
            } catch {
                fatalError()
            }
        }
    }

    /// Re-establishes the connection to the same server without stopping the tunnel: resolves the server hostname
    /// again, points the peer at the result and asks the backend for new UDP sockets. Keys, the peer and the network
    /// settings stay the same, so neither the system nor the app sees a change.
    ///
    /// Use it when the tunnel looks dead although the network is up, for example when the sockets are stuck on a network
    /// that is gone, or the server moved to another address. Path updates never resolve the hostname again.
    /// - Parameter completionHandler: completion handler, called on the adapter's queue once the endpoint is updated and
    ///   new sockets are requested. The backend replaces the sockets in the background and may give up (it logs it), so
    ///   success here doesn't mean the tunnel passes traffic again. Not called if the adapter is deallocated meanwhile.
    public func reconnect(completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        resolveEndpointsAgain { [weak self] resolvedSettingsGenerator in
            guard let self = self else { return }
            guard case .started(let handle, let settingsGenerator) = self.state else {
                completionHandler(.invalidState)
                return
            }

            let generator = resolvedSettingsGenerator ?? settingsGenerator
            let (wgConfig, resolutionResults) = generator.endpointUapiConfiguration()
            self.logEndpointResolutionResults(resolutionResults)

            wgSetConfig(handle, wgConfig)
            #if os(iOS)
            wgDisableSomeRoamingForBrokenMobileSemantics(handle)
            #endif
            wgBumpSockets(handle)

            self.state = .started(handle, generator)
            self.logHandler(.verbose, "Updated the endpoint and requested new sockets.")
            completionHandler(nil)
        }
    }

    /// Replaces the WireGuard backend with a new one for the same configuration, without stopping the tunnel: new
    /// sockets on a new port, a new handshake, and the server hostname resolved again. The network settings stay the
    /// same, so neither the system nor the app sees a change, but packets in flight are lost.
    ///
    /// Heavier than `reconnect(completionHandler:)`. Use it when `reconnect` did not help, for example when the backend
    /// gave up opening its sockets.
    /// - Parameter completionHandler: completion handler, called on the adapter's queue. Not called if the adapter is
    ///   deallocated meanwhile. If starting the new backend fails, the adapter is left without a backend in the temporary
    ///   shutdown state, and calling this method again retries. On iOS, while the network is offline, it does nothing
    ///   and fails with `invalidState`: the adapter starts the backend itself when the network returns.
    public func restartBackend(completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        resolveEndpointsAgain { [weak self] resolvedSettingsGenerator in
            guard let self = self else { return }
            let settingsGenerator: PacketTunnelSettingsGenerator
            switch self.state {
            case .started(let handle, let currentSettingsGenerator):
                wgTurnOff(handle)
                settingsGenerator = currentSettingsGenerator
            case .temporaryShutdown(let currentSettingsGenerator):
                #if os(iOS)
                // On iOS this state also means the network is offline. Starting now would override that; the next
                // satisfiable path update starts the backend anyway.
                if self.networkMonitor?.currentPath.status.isSatisfiable == false {
                    self.logHandler(.verbose, "Not restarting the backend while the network is offline.")
                    completionHandler(.invalidState)
                    return
                }
                #endif
                settingsGenerator = currentSettingsGenerator
            case .stopped:
                completionHandler(.invalidState)
                return
            }

            let generator = resolvedSettingsGenerator ?? settingsGenerator
            let (wgConfig, resolutionResults) = generator.uapiConfiguration()
            self.logEndpointResolutionResults(resolutionResults)

            do {
                self.state = .started(try self.startWireGuardBackend(wgConfig: wgConfig), generator)
                self.logHandler(.verbose, "Restarted the backend.")
                completionHandler(nil)
            } catch let error as WireGuardAdapterError {
                self.state = .temporaryShutdown(generator)
                self.logHandler(.error, "Failed to restart backend: \(error.localizedDescription)")
                completionHandler(error)
            } catch {
                fatalError()
            }
        }
    }

    // MARK: - Private methods

    /// Resolves the hostnames of the current configuration again, away from `workQueue`, because DNS can take long on a
    /// bad network and path updates or `stop` must not wait for it. Calls `body` on `workQueue` with the new settings
    /// generator, or `nil` if the tunnel is stopped, the hostnames could not be resolved, or the configuration changed
    /// (`update`, `stop` and `start`) while resolving. Doesn't call `body` if the adapter is deallocated meanwhile.
    private func resolveEndpointsAgain(then body: @escaping (PacketTunnelSettingsGenerator?) -> Void) {
        workQueue.async { [weak self] in
            guard let self = self else { return }
            guard let tunnelConfiguration = self.state.settingsGenerator?.tunnelConfiguration else {
                body(nil)
                return
            }

            DispatchQueue.global(qos: .utility).async { [weak self] in
                guard let self = self else { return }
                var settingsGenerator: PacketTunnelSettingsGenerator?
                do {
                    settingsGenerator = try self.makeSettingsGenerator(with: tunnelConfiguration)
                } catch {
                    self.logHandler(.error, "Could not resolve the endpoints again, keeping the last known addresses: \(error.localizedDescription)")
                }
                self.workQueue.async { [weak self] in
                    guard let self = self else { return }
                    // The result describes the configuration from before the lookup. Applying it after a change would
                    // bring the old peer back.
                    guard self.state.settingsGenerator?.tunnelConfiguration === tunnelConfiguration else {
                        self.logHandler(.verbose, "The configuration changed while resolving the endpoints; ignoring the result.")
                        body(nil)
                        return
                    }
                    body(settingsGenerator)
                }
            }
        }
    }

    /// Setup WireGuard log handler.
    private func setupLogHandler() {
        let context = Unmanaged.passUnretained(self).toOpaque()
        wgSetLogger(context) { context, logLevel, message in
            guard let context = context, let message = message else { return }

            let unretainedSelf = Unmanaged<WireGuardAdapter>.fromOpaque(context)
                .takeUnretainedValue()

            let swiftString = String(cString: message).trimmingCharacters(in: .newlines)
            let tunnelLogLevel = WireGuardLogLevel(rawValue: logLevel) ?? .verbose

            unretainedSelf.logHandler(tunnelLogLevel, swiftString)
        }
    }

    /// Set network tunnel configuration.
    /// This method ensures that the call to `setTunnelNetworkSettings` does not time out, as in
    /// certain scenarios the completion handler given to it may not be invoked by the system.
    ///
    /// - Parameters:
    ///   - networkSettings: an instance of type `NEPacketTunnelNetworkSettings`.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: `PacketTunnelSettingsGenerator`.
    private func setNetworkSettings(_ networkSettings: NEPacketTunnelNetworkSettings) throws {
        // The system calls the completion handler on its own queue, possibly before we start waiting. A semaphore keeps
        // that signal, while `NSCondition.signal()` without anyone waiting is lost and turns into the 5 second timeout.
        let semaphore = DispatchSemaphore(value: 0)
        let errorLock = NSLock()
        var systemError: Error?

        self.packetTunnelProvider?.setTunnelNetworkSettings(networkSettings) { error in
            errorLock.lock()
            systemError = error
            errorLock.unlock()
            semaphore.signal()
        }

        // Packet tunnel's `setTunnelNetworkSettings` times out in certain
        // scenarios & never calls the given callback.
        let setTunnelNetworkSettingsTimeout: TimeInterval = 5 // seconds

        if semaphore.wait(timeout: .now() + setTunnelNetworkSettingsTimeout) == .timedOut {
            self.logHandler(.error, "setTunnelNetworkSettings timed out after 5 seconds; proceeding anyway")
            return
        }

        errorLock.lock()
        let error = systemError
        errorLock.unlock()
        if let error = error {
            throw WireGuardAdapterError.setNetworkSettings(error)
        }
    }

    /// Resolve peers of the given tunnel configuration.
    /// - Parameter tunnelConfiguration: tunnel configuration.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: The list of resolved endpoints.
    private func resolvePeers(for tunnelConfiguration: TunnelConfiguration) throws -> [Endpoint?] {
        let endpoints = tunnelConfiguration.peers.map { $0.endpoint }
        let resolutionResults = DNSResolver.resolveSync(endpoints: endpoints)
        let resolutionErrors = resolutionResults.compactMap { result -> DNSResolutionError? in
            if case .failure(let error) = result {
                return error
            } else {
                return nil
            }
        }
        assert(endpoints.count == resolutionResults.count)
        guard resolutionErrors.isEmpty else {
            throw WireGuardAdapterError.dnsResolution(resolutionErrors)
        }

        let resolvedEndpoints = resolutionResults.map { result -> Endpoint? in
            // swiftlint:disable:next force_try
            return try! result?.get()
        }

        return resolvedEndpoints
    }

    /// Start WireGuard backend.
    /// - Parameter wgConfig: WireGuard configuration
    /// - Throws: an error of type `WireGuardAdapterError`
    /// - Returns: tunnel handle
    private func startWireGuardBackend(wgConfig: String) throws -> Int32 {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else {
            throw WireGuardAdapterError.cannotLocateTunnelFileDescriptor
        }

        let handle = wgTurnOn(wgConfig, tunnelFileDescriptor)
        if handle < 0 {
            throw WireGuardAdapterError.startWireGuardBackend(handle)
        }
        #if os(iOS)
        wgDisableSomeRoamingForBrokenMobileSemantics(handle)
        #endif
        return handle
    }

    /// Resolves the hostnames in the given tunnel configuration and return settings generator.
    /// - Parameter tunnelConfiguration: an instance of type `TunnelConfiguration`.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: an instance of type `PacketTunnelSettingsGenerator`.
    private func makeSettingsGenerator(with tunnelConfiguration: TunnelConfiguration) throws -> PacketTunnelSettingsGenerator {
        return PacketTunnelSettingsGenerator(
            tunnelConfiguration: tunnelConfiguration,
            resolvedEndpoints: try self.resolvePeers(for: tunnelConfiguration)
        )
    }

    /// Log DNS resolution results.
    /// - Parameter resolutionErrors: an array of type `[DNSResolutionError]`.
    private func logEndpointResolutionResults(_ resolutionResults: [EndpointResolutionResult?]) {
        for case .some(let result) in resolutionResults {
            switch result {
            case .success((let sourceEndpoint, let resolvedEndpoint)):
                if sourceEndpoint.host == resolvedEndpoint.host {
                    self.logHandler(.verbose, "DNS64: mapped \(sourceEndpoint.host) to itself.")
                } else {
                    self.logHandler(.verbose, "DNS64: mapped \(sourceEndpoint.host) to \(resolvedEndpoint.host)")
                }
            case .failure(let resolutionError):
                self.logHandler(.error, "Failed to resolve endpoint \(resolutionError.address): \(resolutionError.errorDescription ?? "(nil)")")
            }
        }
    }

    /// Switching between Wi-Fi and cellular delivers several path updates in a row. Handling each of them resets the
    /// sockets again and again, so only the last update of a short burst is handled. Called on `workQueue`.
    /// - Parameter path: new network path
    private func schedulePathUpdate(_ path: Network.NWPath) {
        pendingPathUpdate?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            self?.pendingPathUpdate = nil
            self?.didReceivePathUpdate(path: path)
        }
        pendingPathUpdate = workItem
        workQueue.asyncAfter(deadline: .now() + Self.pathUpdateDebounceInterval, execute: workItem)
    }

    /// Helper method used by network path monitor.
    /// - Parameter path: new network path
    private func didReceivePathUpdate(path: Network.NWPath) {
        self.logHandler(.verbose, "Network change detected with \(path.status) route and interface order \(path.availableInterfaces)")

        #if os(macOS) || os(tvOS)
        if case .started(let handle, _) = self.state {
            wgBumpSockets(handle)
        }
        #elseif os(iOS)
        switch self.state {
        case .started(let handle, let settingsGenerator):
            if path.status.isSatisfiable {
                let (wgConfig, resolutionResults) = settingsGenerator.endpointUapiConfiguration()
                self.logEndpointResolutionResults(resolutionResults)

                wgSetConfig(handle, wgConfig)
                wgDisableSomeRoamingForBrokenMobileSemantics(handle)
                wgBumpSockets(handle)
            } else {
                self.logHandler(.verbose, "Connectivity offline, pausing backend.")

                self.state = .temporaryShutdown(settingsGenerator)
                wgTurnOff(handle)
            }

        case .temporaryShutdown(let settingsGenerator):
            guard path.status.isSatisfiable else { return }

            self.logHandler(.verbose, "Connectivity online, resuming backend.")

            do {
                try self.setNetworkSettings(settingsGenerator.generateNetworkSettings())

                let (wgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                self.logEndpointResolutionResults(resolutionResults)

                self.state = .started(
                    try self.startWireGuardBackend(wgConfig: wgConfig),
                    settingsGenerator
                )
            } catch {
                self.logHandler(.error, "Failed to restart backend: \(error.localizedDescription)")
            }

        case .stopped:
            // no-op
            break
        }
        #else
        #error("Unsupported")
        #endif
    }
}

/// A enum describing WireGuard log levels defined in `api-apple.go`.
public enum WireGuardLogLevel: Int32 {
    case verbose = 0
    case error = 1
}

private extension Network.NWPath.Status {
    /// Returns `true` if the path is potentially satisfiable.
    var isSatisfiable: Bool {
        switch self {
        case .requiresConnection, .satisfied:
            return true
        case .unsatisfied:
            return false
        @unknown default:
            return true
        }
    }
}
