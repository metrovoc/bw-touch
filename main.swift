import Darwin
import Foundation
import LocalAuthentication
import Security

private let service = "bitwarden.cli-master-password"
private let account = "user@example.com"
private let bwPath = "/opt/homebrew/bin/bw"
private let ttl: TimeInterval = 15 * 60
private let socketPath = FileManager.default.temporaryDirectory
    .appendingPathComponent("bw-touch-\(getuid()).sock").path

private struct Request: Codable {
    let arguments: [String]
}

private struct Response: Codable {
    let status: Int32
    let stdout: String
    let stderr: String
}

private enum ToolError: Error, CustomStringConvertible {
    case message(String)

    var description: String {
        switch self {
        case .message(let value): return value
        }
    }
}

private func secureRead(_ prompt: String) throws -> Data {
    FileHandle.standardError.write(Data(prompt.utf8))
    var original = termios()
    guard tcgetattr(STDIN_FILENO, &original) == 0 else {
        throw ToolError.message("Unable to read terminal settings")
    }
    var hidden = original
    hidden.c_lflag &= ~tcflag_t(ECHO)
    guard tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0 else {
        throw ToolError.message("Unable to disable terminal echo")
    }
    defer {
        var restore = original
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &restore)
        FileHandle.standardError.write(Data("\n".utf8))
    }
    guard let line = readLine(strippingNewline: true), !line.isEmpty else {
        throw ToolError.message("Password cannot be empty")
    }
    return Data(line.utf8)
}

private func keychainBaseQuery() -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
    ]
}

private func setupCredential() throws {
    var existing = keychainBaseQuery()
    existing[kSecReturnAttributes as String] = true
    var result: CFTypeRef?
    let existingStatus = SecItemCopyMatching(existing as CFDictionary, &result)
    if existingStatus == errSecSuccess {
        throw ToolError.message("Credential already exists for \(account)")
    }
    guard existingStatus == errSecItemNotFound else {
        throw ToolError.message("Keychain lookup failed: \(existingStatus)")
    }

    let first = try secureRead("Bitwarden master password: ")
    let second = try secureRead("Confirm master password: ")
    guard first == second else {
        throw ToolError.message("Passwords do not match")
    }

    var accessError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .biometryCurrentSet,
        &accessError
    ) else {
        let detail = accessError?.takeRetainedValue().localizedDescription ?? "unknown error"
        throw ToolError.message("Unable to create Touch ID policy: \(detail)")
    }

    var item = keychainBaseQuery()
    item[kSecValueData as String] = first
    item[kSecAttrLabel as String] = "Bitwarden CLI master password"
    item[kSecAttrDescription as String] = "Touch ID protected credential for bw-touch"
    item[kSecAttrAccessControl as String] = access
    let status = SecItemAdd(item as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw ToolError.message("Unable to store credential: \(status)")
    }
    FileHandle.standardOutput.write(Data("Touch ID credential stored.\n".utf8))
}

private func readCredential() throws -> String {
    var query = keychainBaseQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    let context = LAContext()
    context.localizedReason = "Unlock Bitwarden CLI for 15 minutes"
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data,
          let value = String(data: data, encoding: .utf8) else {
        throw ToolError.message("Touch ID authorization failed: \(status)")
    }
    return value
}

private func runProcess(arguments: [String], extraEnvironment: [String: String] = [:]) throws -> Response {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: bwPath)
    process.arguments = arguments
    var environment = ProcessInfo.processInfo.environment
    for (key, value) in extraEnvironment { environment[key] = value }
    process.environment = environment

    let output = Pipe()
    let errors = Pipe()
    process.standardOutput = output
    process.standardError = errors
    try process.run()

    let group = DispatchGroup()
    var outputData = Data()
    var errorData = Data()
    group.enter()
    DispatchQueue.global().async {
        outputData = output.fileHandleForReading.readDataToEndOfFile()
        group.leave()
    }
    group.enter()
    DispatchQueue.global().async {
        errorData = errors.fileHandleForReading.readDataToEndOfFile()
        group.leave()
    }
    process.waitUntilExit()
    group.wait()

    return Response(
        status: process.terminationStatus,
        stdout: String(data: outputData, encoding: .utf8) ?? "",
        stderr: String(data: errorData, encoding: .utf8) ?? ""
    )
}

private func unlockSession() throws -> String {
    let password = try readCredential()
    let response = try runProcess(
        arguments: ["unlock", "--passwordenv", "BW_TOUCH_MASTER", "--raw"],
        extraEnvironment: ["BW_TOUCH_MASTER": password]
    )
    guard response.status == 0 else {
        throw ToolError.message(response.stderr.isEmpty ? "Bitwarden unlock failed" : response.stderr)
    }
    let session = response.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !session.isEmpty else { throw ToolError.message("Bitwarden returned an empty session") }
    return session
}

private func makeAddress() throws -> sockaddr_un {
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let bytes = Array(socketPath.utf8CString)
    let capacity = MemoryLayout.size(ofValue: address.sun_path)
    guard bytes.count <= capacity else { throw ToolError.message("Socket path is too long") }
    _ = socketPath.withCString { source in
        withUnsafeMutablePointer(to: &address.sun_path) { pathPointer in
            pathPointer.withMemoryRebound(to: CChar.self, capacity: capacity) { destination in
                strlcpy(destination, source, capacity)
            }
        }
    }
    return address
}

private func withSocketAddress<T>(_ address: inout sockaddr_un, _ body: (UnsafePointer<sockaddr>, socklen_t) -> T) -> T {
    withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            body($0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
}

private func writeAll(_ fd: Int32, data: Data) throws {
    try data.withUnsafeBytes { rawBuffer in
        guard let base = rawBuffer.baseAddress else { return }
        var sent = 0
        while sent < rawBuffer.count {
            let count = Darwin.write(fd, base.advanced(by: sent), rawBuffer.count - sent)
            guard count > 0 else { throw ToolError.message("Socket write failed") }
            sent += count
        }
    }
}

private func readAll(_ fd: Int32) throws -> Data {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 8192)
    while true {
        let count = Darwin.read(fd, &buffer, buffer.count)
        if count == 0 { break }
        guard count > 0 else { throw ToolError.message("Socket read failed") }
        data.append(buffer, count: count)
    }
    return data
}

private func connectSocket() throws -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw ToolError.message("Unable to create client socket") }
    var address = try makeAddress()
    let status = withSocketAddress(&address) { Darwin.connect(fd, $0, $1) }
    if status != 0 {
        close(fd)
        throw ToolError.message("Agent is unavailable")
    }
    return fd
}

private func spawnAgent() throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: URL(fileURLWithPath: CommandLine.arguments[0]).standardized.path)
    process.arguments = ["--daemon"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
}

private func sendRequest(_ arguments: [String]) throws -> Response {
    var fd: Int32 = -1
    for attempt in 0..<30 {
        if let connected = try? connectSocket() {
            fd = connected
            break
        }
        if attempt == 0 { try spawnAgent() }
        usleep(100_000)
    }
    guard fd >= 0 else { throw ToolError.message("Unable to start bw-touch agent") }
    defer { close(fd) }

    try writeAll(fd, data: try JSONEncoder().encode(Request(arguments: arguments)))
    shutdown(fd, SHUT_WR)
    return try JSONDecoder().decode(Response.self, from: readAll(fd))
}

private func runDaemon() throws {
    unlink(socketPath)
    let server = socket(AF_UNIX, SOCK_STREAM, 0)
    guard server >= 0 else { throw ToolError.message("Unable to create agent socket") }
    defer {
        close(server)
        unlink(socketPath)
    }
    var address = try makeAddress()
    guard withSocketAddress(&address, { Darwin.bind(server, $0, $1) }) == 0 else {
        throw ToolError.message("Unable to bind agent socket")
    }
    chmod(socketPath, S_IRUSR | S_IWUSR)
    guard listen(server, 8) == 0 else { throw ToolError.message("Unable to listen on agent socket") }

    var session: String?
    var lastUsed = Date()
    var shouldExit = false
    while !shouldExit {
        let remaining = max(0, ttl - Date().timeIntervalSince(lastUsed))
        var descriptor = pollfd(fd: server, events: Int16(POLLIN), revents: 0)
        let pollStatus = poll(&descriptor, 1, Int32(remaining * 1000))
        if pollStatus == 0 { break }
        if pollStatus < 0 {
            if errno == EINTR { continue }
            throw ToolError.message("Agent poll failed")
        }
        let client = accept(server, nil, nil)
        guard client >= 0 else { continue }
        do {
            let request = try JSONDecoder().decode(Request.self, from: readAll(client))
            if request.arguments == ["lock"] {
                let response = try runProcess(arguments: ["lock"])
                try writeAll(client, data: try JSONEncoder().encode(response))
                session = nil
                shouldExit = true
            } else {
                if session == nil { session = try unlockSession() }
                let response = try runProcess(arguments: request.arguments, extraEnvironment: ["BW_SESSION": session!])
                try writeAll(client, data: try JSONEncoder().encode(response))
                lastUsed = Date()
            }
        } catch {
            let response = Response(status: 1, stdout: "", stderr: "\(error)\n")
            if let data = try? JSONEncoder().encode(response) { try? writeAll(client, data: data) }
        }
        close(client)
    }
    if session != nil { _ = try? runProcess(arguments: ["lock"]) }
}

private func main() -> Int32 {
    do {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments == ["setup"] {
            try setupCredential()
            return 0
        }
        if arguments == ["--daemon"] {
            try runDaemon()
            return 0
        }
        if arguments.isEmpty {
            FileHandle.standardError.write(Data("Usage: bw-touch setup | bw-touch <bw arguments>\n".utf8))
            return 2
        }
        let response = try sendRequest(arguments)
        FileHandle.standardOutput.write(Data(response.stdout.utf8))
        FileHandle.standardError.write(Data(response.stderr.utf8))
        return response.status
    } catch {
        FileHandle.standardError.write(Data("bw-touch: \(error)\n".utf8))
        return 1
    }
}

exit(main())
