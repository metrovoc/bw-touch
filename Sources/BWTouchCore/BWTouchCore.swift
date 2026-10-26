import Darwin
import Foundation
import LocalAuthentication
import Security

let service = "bitwarden.cli-master-password"
let account = "user@example.com"
let bwPath = "/opt/homebrew/bin/bw"
let ttl: TimeInterval = 15 * 60
let leaseTTL: TimeInterval = 24 * 60 * 60
let touchIDTimeout: TimeInterval = 60
let runtimeDirectory = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Caches/bw-touch", isDirectory: true)
let socketPath = runtimeDirectory.appendingPathComponent("agent.sock").path
let lockPath = runtimeDirectory.appendingPathComponent("agent.lock").path

struct Request: Codable {
    let arguments: [String]
    let standardInput: Data?

    init(arguments: [String], standardInput: Data? = nil) {
        self.arguments = arguments
        self.standardInput = standardInput
    }
}

struct Response: Codable, Equatable {
    let status: Int32
    let stdout: String
    let stderr: String
}

struct VaultStatus: Codable {
    let status: String
}

typealias ProcessRunner = (
    _ arguments: [String],
    _ extraEnvironment: [String: String],
    _ standardInput: Data?
) throws -> Response

enum ToolError: Error, CustomStringConvertible {
    case message(String)

    var description: String {
        switch self {
        case .message(let value): return value
        }
    }
}

func secureRead(_ prompt: String) throws -> Data {
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

func zeroize(_ data: inout Data) {
    data.resetBytes(in: 0..<data.count)
    data.removeAll(keepingCapacity: false)
}

func keychainBaseQuery() -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
}

func resolvedExecutablePath(_ executableURL: URL?) throws -> String {
    guard let executableURL else {
        throw ToolError.message("Unable to resolve the bw-touch executable")
    }
    return executableURL.resolvingSymlinksInPath().path
}

func executablePath() throws -> String {
    try resolvedExecutablePath(Bundle.main.executableURL)
}

func trustedApplicationAccess(label: String) throws -> SecAccess {
    let executablePath = try executablePath()
    var trustedApplication: SecTrustedApplication?
    let trustedStatus = SecTrustedApplicationCreateFromPath(executablePath, &trustedApplication)
    guard trustedStatus == errSecSuccess, let trustedApplication else {
        throw ToolError.message("Unable to bind credential to bw-touch: \(trustedStatus)")
    }
    var access: SecAccess?
    let accessStatus = SecAccessCreate(label as CFString, [trustedApplication] as CFArray, &access)
    guard accessStatus == errSecSuccess, let access else {
        throw ToolError.message("Unable to create Keychain access policy: \(accessStatus)")
    }
    return access
}

func authenticateWithTouchID() throws {
    let context = LAContext()
    context.localizedReason = "Unlock Bitwarden CLI for 15 minutes and keep the items read available for 24 hours"
    var capabilityError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &capabilityError) else {
        throw ToolError.message(capabilityError?.localizedDescription ?? "Touch ID is unavailable")
    }

    let semaphore = DispatchSemaphore(value: 0)
    var authenticated = false
    var authenticationError: Error?
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: context.localizedReason) {
        success, error in
        authenticated = success
        authenticationError = error
        semaphore.signal()
    }
    // An unanswered prompt would otherwise stall every request queued behind it.
    guard semaphore.wait(timeout: .now() + touchIDTimeout) == .success else {
        context.invalidate()
        throw ToolError.message("Touch ID prompt timed out")
    }
    guard authenticated else {
        throw ToolError.message(authenticationError?.localizedDescription ?? "Touch ID authorization failed")
    }
}

func setupCredential() throws {
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

    var first = try secureRead("Bitwarden master password: ")
    var second = try secureRead("Confirm master password: ")
    defer {
        zeroize(&first)
        zeroize(&second)
    }
    guard first == second else {
        throw ToolError.message("Passwords do not match")
    }

    var item = keychainBaseQuery()
    item[kSecValueData as String] = first
    item[kSecAttrLabel as String] = "Bitwarden CLI master password"
    item[kSecAttrDescription as String] = "Touch ID protected credential for bw-touch"
    item[kSecAttrAccess as String] = try trustedApplicationAccess(label: "Bitwarden CLI master password")
    let status = SecItemAdd(item as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw ToolError.message("Unable to store credential: \(status)")
    }
    FileHandle.standardOutput.write(Data("Touch ID credential stored.\n".utf8))
}

func selfTestKeychain(
    service testService: String = "bitwarden.cli-keychain-self-test",
    account testAccount: String = "bw-touch"
) throws {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: testService,
        kSecAttrAccount as String: testAccount,
    ]
    var existing: CFTypeRef?
    let existingStatus = SecItemCopyMatching(query as CFDictionary, &existing)
    guard existingStatus == errSecItemNotFound else {
        throw ToolError.message("Self-test identity already exists: \(existingStatus)")
    }

    let expected = Data("non-secret-self-test".utf8)
    query[kSecValueData as String] = expected
    query[kSecAttrAccess as String] = try trustedApplicationAccess(label: "bw-touch self-test")
    let addStatus = SecItemAdd(query as CFDictionary, nil)
    guard addStatus == errSecSuccess else {
        throw ToolError.message("Self-test add failed: \(addStatus)")
    }
    defer {
        var deleteQuery = query
        deleteQuery.removeValue(forKey: kSecValueData as String)
        deleteQuery.removeValue(forKey: kSecAttrAccess as String)
        SecItemDelete(deleteQuery as CFDictionary)
    }

    query.removeValue(forKey: kSecValueData as String)
    query.removeValue(forKey: kSecAttrAccess as String)
    query[kSecReturnData as String] = true
    var result: CFTypeRef?
    let readStatus = SecItemCopyMatching(query as CFDictionary, &result)
    guard readStatus == errSecSuccess, let actual = result as? Data, actual == expected else {
        throw ToolError.message("Self-test read failed: \(readStatus)")
    }
    FileHandle.standardOutput.write(Data("Keychain ACL self-test passed.\n".utf8))
}

func readCredential() throws -> Data {
    var query = keychainBaseQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data, !data.isEmpty else {
        throw ToolError.message("Unable to read Bitwarden credential: \(status)")
    }
    return data
}

func runProcess(
    executablePath: String = bwPath,
    arguments: [String],
    extraEnvironment: [String: String] = [:],
    standardInput: Data? = nil
) throws -> Response {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executablePath)
    process.arguments = arguments
    var environment = ProcessInfo.processInfo.environment
    environment.removeValue(forKey: "BW_SESSION")
    environment.removeValue(forKey: "BW_NOINTERACTION")
    environment.removeValue(forKey: "BW_TOUCH_MASTER")
    for (key, value) in extraEnvironment { environment[key] = value }
    process.environment = environment

    let output = Pipe()
    let errors = Pipe()
    let input = standardInput == nil ? nil : Pipe()
    process.standardOutput = output
    process.standardError = errors
    process.standardInput = input ?? FileHandle.nullDevice
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
    if let standardInput, let input {
        try? input.fileHandleForWriting.write(contentsOf: standardInput)
        try? input.fileHandleForWriting.write(contentsOf: Data([0x0a]))
        try? input.fileHandleForWriting.close()
    }
    process.waitUntilExit()
    group.wait()

    return Response(
        status: process.terminationStatus,
        stdout: String(data: outputData, encoding: .utf8) ?? "",
        stderr: String(data: errorData, encoding: .utf8) ?? ""
    )
}

func parseVaultStatus(_ response: Response) throws -> VaultStatus {
    guard response.status == 0,
          let data = response.stdout.data(using: .utf8),
          let status = try? JSONDecoder().decode(VaultStatus.self, from: data) else {
        throw ToolError.message(response.stderr.isEmpty ? "Unable to read Bitwarden status" : response.stderr)
    }
    return status
}

func removingPasswordPrompt(from text: String) -> String {
    let withoutANSI = text.replacingOccurrences(
        of: "\u{001B}\\[[0-9;?]*[ -/]*[@-~]",
        with: "",
        options: .regularExpression
    )
    guard withoutANSI.localizedCaseInsensitiveContains("Master password:") else {
        return text
    }
    return withoutANSI
        .components(separatedBy: .newlines)
        .filter { !$0.localizedCaseInsensitiveContains("Master password:") }
        .joined(separator: "\n")
        .trimmingCharacters(in: .whitespacesAndNewlines)
}

func removingPasswordPrompt(from response: Response) -> Response {
    Response(
        status: response.status,
        stdout: response.stdout,
        stderr: removingPasswordPrompt(from: response.stderr)
    )
}

func isLockedResponse(_ response: Response) -> Bool {
    response.status != 0 && removingPasswordPrompt(from: response.stderr)
        .trimmingCharacters(in: .whitespacesAndNewlines) == "Vault is locked."
}

func leaseItemID(for arguments: [String]) -> String? {
    guard arguments.count == 3, arguments[0] == "get",
          ["item", "username", "password", "uri", "totp", "notes"].contains(arguments[1]),
          UUID(uuidString: arguments[2]) != nil else { return nil }
    return arguments[2].lowercased()
}

func withCredential<T>(
    from reader: () throws -> Data,
    perform operation: (Data) throws -> T
) throws -> T {
    var credential = try reader()
    defer { zeroize(&credential) }
    return try operation(credential)
}

func executeCommand(
    _ arguments: [String],
    authorize: () throws -> Void,
    credentialReader: () throws -> Data = readCredential,
    processRunner: ProcessRunner = {
        try runProcess(arguments: $0, extraEnvironment: $1, standardInput: $2)
    }
) throws -> Response {
    func retryAfterInlineUnlock(_ response: Response) throws -> Response {
        guard isLockedResponse(response) else { return response }
        try authorize()
        return try withCredential(from: credentialReader) {
            try processRunner(arguments, [:], $0)
        }
    }

    var response = try processRunner(arguments, ["BW_NOINTERACTION": "true"], nil)
    if isLockedResponse(response) {
        return removingPasswordPrompt(from: try retryAfterInlineUnlock(response))
    }

    if response.status != 0 {
        let statusResponse = try processRunner(["status"], ["BW_NOINTERACTION": "true"], nil)
        if let status = try? parseVaultStatus(statusResponse), status.status == "unauthenticated" {
            try authorize()
            let login = try withCredential(from: credentialReader) {
                try processRunner(["login", account, "--quiet"], [:], $0)
            }
            let cleanedLogin = removingPasswordPrompt(from: login)
            guard cleanedLogin.status == 0 else { return cleanedLogin }

            response = try processRunner(arguments, ["BW_NOINTERACTION": "true"], nil)
            response = try retryAfterInlineUnlock(response)
        }
    }

    return removingPasswordPrompt(from: response)
}

func makeAddress(path: String = socketPath) throws -> sockaddr_un {
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let bytes = Array(path.utf8CString)
    let capacity = MemoryLayout.size(ofValue: address.sun_path)
    guard bytes.count <= capacity else { throw ToolError.message("Socket path is too long") }
    _ = path.withCString { source in
        withUnsafeMutablePointer(to: &address.sun_path) { pathPointer in
            pathPointer.withMemoryRebound(to: CChar.self, capacity: capacity) { destination in
                strlcpy(destination, source, capacity)
            }
        }
    }
    return address
}

func prepareRuntimeDirectory(at directory: URL = runtimeDirectory) throws {
    var metadata = stat()
    if lstat(directory.path, &metadata) == 0 {
        guard metadata.st_uid == getuid(), metadata.st_mode & S_IFMT == S_IFDIR else {
            throw ToolError.message("Unsafe bw-touch runtime directory")
        }
    } else {
        guard errno == ENOENT else {
            throw ToolError.message("Unable to inspect bw-touch runtime directory")
        }
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }
    guard chmod(directory.path, S_IRWXU) == 0 else {
        throw ToolError.message("Unable to secure bw-touch runtime directory")
    }
}

func acquireAgentLock(path: String) throws -> Int32 {
    let descriptor = open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
    guard descriptor >= 0 else { throw ToolError.message("Unable to open bw-touch agent lock") }
    guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
        close(descriptor)
        throw ToolError.message("bw-touch agent is already running")
    }
    return descriptor
}

func withSocketAddress<T>(_ address: inout sockaddr_un, _ body: (UnsafePointer<sockaddr>, socklen_t) -> T) -> T {
    withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            body($0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
}

func writeAll(_ fd: Int32, data: Data) throws {
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

func readAll(_ fd: Int32, maximumBytes: Int? = nil) throws -> Data {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 8192)
    while true {
        let count = Darwin.read(fd, &buffer, buffer.count)
        if count == 0 { break }
        guard count > 0 else { throw ToolError.message("Socket read failed") }
        if let maximumBytes, count > maximumBytes - data.count {
            throw ToolError.message("Socket request exceeds size limit")
        }
        data.append(buffer, count: count)
    }
    return data
}

func connectSocket(path: String = socketPath) throws -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw ToolError.message("Unable to create client socket") }
    var address = try makeAddress(path: path)
    let status = withSocketAddress(&address) { Darwin.connect(fd, $0, $1) }
    if status != 0 {
        close(fd)
        throw ToolError.message("Agent is unavailable")
    }
    return fd
}

func agentLaunchArguments(executable: String, userID: uid_t = getuid()) -> [String] {
    ["asuser", String(userID), executable, "--daemon"]
}

func spawnAgent(launcherPath: String = "/bin/launchctl") throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: launcherPath)
    process.arguments = agentLaunchArguments(executable: try executablePath())
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
}

func sendRequest(
    _ arguments: [String],
    standardInput: Data? = nil,
    path: String = socketPath,
    spawn: () throws -> Void = { try spawnAgent() }
) throws -> Response {
    var fd: Int32 = -1
    for attempt in 0..<30 {
        if let connected = try? connectSocket(path: path) {
            fd = connected
            break
        }
        if attempt == 0 { try spawn() }
        usleep(100_000)
    }
    guard fd >= 0 else { throw ToolError.message("Unable to start bw-touch agent") }
    defer { close(fd) }

    try writeAll(fd, data: try JSONEncoder().encode(Request(arguments: arguments, standardInput: standardInput)))
    shutdown(fd, SHUT_WR)
    return try JSONDecoder().decode(Response.self, from: readAll(fd))
}

func runDaemon(
    path: String = socketPath,
    lockFilePath: String = lockPath,
    timeout: TimeInterval = ttl,
    leaseDuration: TimeInterval = leaseTTL,
    payloadRunner: (PipedItemOperation, Data) throws -> Response = {
        try runPipedItemOperation($0, credential: $1)
    },
    prepare: () throws -> Void = { try prepareRuntimeDirectory() },
    authenticator: () throws -> Void = authenticateWithTouchID,
    credentialReader: () throws -> Data = readCredential,
    processRunner: ProcessRunner = {
        try runProcess(arguments: $0, extraEnvironment: $1, standardInput: $2)
    }
) throws {
    try prepare()
    let agentLock = try acquireAgentLock(path: lockFilePath)
    defer { close(agentLock) }

    unlink(path)
    let server = socket(AF_UNIX, SOCK_STREAM, 0)
    guard server >= 0 else { throw ToolError.message("Unable to create agent socket") }
    defer {
        close(server)
        unlink(path)
    }
    var address = try makeAddress(path: path)
    guard withSocketAddress(&address, { Darwin.bind(server, $0, $1) }) == 0 else {
        throw ToolError.message("Unable to bind agent socket")
    }
    chmod(path, S_IRUSR | S_IWUSR)
    guard listen(server, 8) == 0 else { throw ToolError.message("Unable to listen on agent socket") }

    var authorized = false
    // Items read by exact ID while authorized stay readable until their lease expires.
    var leases: [String: Date] = [:]
    var lastUsed = Date()
    var shouldExit = false

    func ensureAuthorized() throws {
        if !authorized {
            try authenticator()
            authorized = true
        }
    }

    // Compare wall-clock time: poll timeouts do not advance while the Mac sleeps.
    func expireAuthorization(at now: Date) {
        guard now >= lastUsed.addingTimeInterval(timeout) else { return }
        if authorized {
            _ = try? processRunner(["lock"], [:], nil)
            authorized = false
        }
        leases = leases.filter { $0.value > now }
    }

    func runWithCredential(_ arguments: [String]) throws -> Response {
        try ensureAuthorized()
        var credential = try credentialReader()
        defer { zeroize(&credential) }
        return removingPasswordPrompt(
            from: try processRunner(arguments, [:], credential)
        )
    }

    while !shouldExit {
        let now = Date()
        expireAuthorization(at: now)
        let idleDeadline = lastUsed.addingTimeInterval(timeout)
        guard let deadline = now < idleDeadline ? idleDeadline : leases.values.max() else { break }
        var descriptor = pollfd(fd: server, events: Int16(POLLIN), revents: 0)
        let pollStatus = poll(&descriptor, 1, Int32(max(0, deadline.timeIntervalSince(now)) * 1000))
        if pollStatus == 0 { continue }
        if pollStatus < 0 {
            if errno == EINTR { continue }
            throw ToolError.message("Agent poll failed")
        }
        let client = accept(server, nil, nil)
        guard client >= 0 else { continue }
        // A client that stops waiting must not end the daemon with SIGPIPE.
        var noSigPipe: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        expireAuthorization(at: Date())
        do {
            let request = try JSONDecoder().decode(Request.self, from: readAll(client, maximumBytes: 8 * 1024 * 1024))
            if let input = request.standardInput {
                let operation = try PipedItemOperation(arguments: request.arguments, encodedInput: input)
                try ensureAuthorized()
                let response = try withCredential(from: credentialReader) {
                    try payloadRunner(operation, $0)
                }
                try writeAll(client, data: try JSONEncoder().encode(response))
                lastUsed = Date()
            } else if request.arguments == ["lock"] {
                let response = try processRunner(["lock"], [:], nil)
                try writeAll(client, data: try JSONEncoder().encode(response))
                authorized = false
                shouldExit = true
            } else if request.arguments == ["status"] {
                let response = try processRunner(request.arguments, [:], nil)
                try writeAll(client, data: try JSONEncoder().encode(response))
                lastUsed = Date()
            } else if request.arguments.first == "login" || request.arguments.first == "unlock" {
                var arguments = request.arguments
                if arguments == ["login"] { arguments.append(account) }
                let response = try runWithCredential(arguments)
                try writeAll(client, data: try JSONEncoder().encode(response))
                lastUsed = Date()
            } else if request.arguments.first == "logout" {
                let response = try processRunner(request.arguments, [:], nil)
                try writeAll(client, data: try JSONEncoder().encode(response))
                authorized = false
                shouldExit = true
            } else {
                let itemID = leaseItemID(for: request.arguments)
                let leased = itemID.map { leases[$0, default: .distantPast] > Date() } ?? false
                let response = try executeCommand(
                    request.arguments,
                    authorize: leased ? {} : ensureAuthorized,
                    credentialReader: credentialReader,
                    processRunner: processRunner
                )
                if authorized, response.status == 0, let itemID {
                    leases[itemID] = Date().addingTimeInterval(leaseDuration)
                }
                try writeAll(client, data: try JSONEncoder().encode(response))
                lastUsed = Date()
            }
        } catch {
            let response = Response(status: 1, stdout: "", stderr: "\(error)\n")
            if let data = try? JSONEncoder().encode(response) { try? writeAll(client, data: data) }
        }
        close(client)
    }
}

public func runCLI(arguments: [String]) -> Int32 {
    do {
        if arguments == ["setup"] {
            try setupCredential()
            return 0
        }
        if arguments == ["--self-test-keychain"] {
            try selfTestKeychain()
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
        let input = try commandInput(arguments: arguments, isTerminal: isatty(STDIN_FILENO) == 1) {
            FileHandle.standardInput.readData(ofLength: 64 * 1024)
        }
        let response = try sendRequest(arguments, standardInput: input)
        FileHandle.standardOutput.write(Data(response.stdout.utf8))
        FileHandle.standardError.write(Data(response.stderr.utf8))
        return response.status
    } catch {
        FileHandle.standardError.write(Data("bw-touch: \(error)\n".utf8))
        return 1
    }
}
