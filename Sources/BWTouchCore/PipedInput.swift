import Darwin
import Foundation

let maximumPipedInputBytes = 4 * 1024 * 1024
let maximumPayloadResponseBytes = 16 * 1024 * 1024

func commandInput(
    arguments: [String],
    isTerminal: Bool,
    readChunk: () throws -> Data
) throws -> Data? {
    guard !isTerminal, ["create", "edit"].contains(arguments.first ?? "") else { return nil }
    var input = Data()
    while true {
        let chunk = try readChunk()
        if chunk.isEmpty { return input.isEmpty ? nil : input }
        guard chunk.count <= maximumPipedInputBytes - input.count else {
            throw ToolError.message("Piped input exceeds 4 MiB")
        }
        input.append(chunk)
    }
}

struct PipedItemOperation {
    let method: String
    let path: String
    let body: Data
    let quiet: Bool

    init(arguments: [String], encodedInput: Data) throws {
        guard encodedInput.count <= maximumPipedInputBytes,
              let encoded = String(data: encodedInput, encoding: .utf8),
              let decoded = Data(base64Encoded: encoded.filter { !$0.isWhitespace }),
              let object = try? JSONSerialization.jsonObject(with: decoded) as? [String: Any] else {
            throw ToolError.message("Piped item input must be a base64-encoded JSON object under 4 MiB")
        }
        var args = arguments
        quiet = args.contains("--quiet")
        args.removeAll { $0 == "--quiet" || $0 == "--raw" }
        if args == ["create", "item"] {
            method = "POST"
            path = "/object/item"
        } else if args.count == 3, args[0] == "edit", args[1] == "item",
                  UUID(uuidString: args[2]) != nil {
            method = "PUT"
            path = "/object/item/" + args[2]
        } else {
            throw ToolError.message("Piped input supports create item or edit item <UUID>, with --quiet/--raw")
        }
        body = try JSONSerialization.data(withJSONObject: object)
    }
}

struct PayloadHTTPResponse {
    let status: Int
    let body: Data
}

final class PayloadHTTPClient {
    let descriptor: Int32
    let deadline: Date
    let maximumBodyBytes: Int
    private var buffer = Data()

    init(descriptor: Int32, timeout: TimeInterval = 45,
         maximumBodyBytes: Int = maximumPayloadResponseBytes) throws {
        self.descriptor = descriptor
        deadline = Date().addingTimeInterval(timeout)
        self.maximumBodyBytes = maximumBodyBytes
        var interval = timeval(tv_sec: 0, tv_usec: 100_000)
        var one: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &interval,
                         socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &interval,
                         socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &one,
                         socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw ToolError.message("Unable to configure private payload socket")
        }
    }

    private func checkDeadline() throws {
        guard Date() < deadline else { throw ToolError.message("Bitwarden payload operation timed out") }
    }

    private func readMore() throws {
        var chunk = [UInt8](repeating: 0, count: 8192)
        while true {
            try checkDeadline()
            let count = Darwin.read(descriptor, &chunk, chunk.count)
            if count > 0 { buffer.append(chunk, count: count); return }
            if count < 0 && [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            throw ToolError.message("Bitwarden payload connection closed unexpectedly")
        }
    }

    private func take(_ count: Int) throws -> Data {
        while buffer.count < count { try readMore() }
        let data = Data(buffer.prefix(count))
        buffer.removeFirst(count)
        return data
    }

    private func line(maximumBytes: Int) throws -> Data {
        let delimiter = Data([13, 10])
        while true {
            if let range = buffer.range(of: delimiter) {
                let count = buffer.distance(from: buffer.startIndex, to: range.lowerBound)
                guard count <= maximumBytes else { throw ToolError.message("Bitwarden response header is too large") }
                let value = try take(count)
                _ = try take(2)
                return value
            }
            guard buffer.count <= maximumBytes else { throw ToolError.message("Bitwarden response header is too large") }
            try readMore()
        }
    }

    private func write(_ data: Data) throws {
        try data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            var offset = 0
            while offset < bytes.count {
                try checkDeadline()
                let count = Darwin.write(descriptor, base.advanced(by: offset), bytes.count - offset)
                if count > 0 { offset += count; continue }
                if count < 0 && [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
                throw ToolError.message("Bitwarden payload socket write failed")
            }
        }
    }

    func request(method: String, path: String, body: Data) throws -> PayloadHTTPResponse {
        let header = "\(method) \(path) HTTP/1.1\r\nHost: bw-touch\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: keep-alive\r\n\r\n"
        try write(Data(header.utf8))
        try write(body)
        let statusLine = String(decoding: try line(maximumBytes: 8192), as: UTF8.self).split(separator: " ")
        guard statusLine.count >= 2, statusLine[0].hasPrefix("HTTP/1."),
              let status = Int(statusLine[1]) else { throw ToolError.message("Invalid Bitwarden HTTP response") }
        var headers: [String: String] = [:]
        var headerBytes = 0
        while true {
            let data = try line(maximumBytes: 8192)
            headerBytes += data.count + 2
            guard headerBytes <= 65536 else { throw ToolError.message("Bitwarden response headers exceed limit") }
            if data.isEmpty { break }
            let fields = String(decoding: data, as: UTF8.self).split(separator: ":", maxSplits: 1)
            guard fields.count == 2 else { throw ToolError.message("Invalid Bitwarden response header") }
            let name = fields[0].lowercased()
            guard headers[name] == nil else { throw ToolError.message("Duplicate Bitwarden response header") }
            headers[name] = fields[1].trimmingCharacters(in: .whitespaces)
        }
        var responseBody = Data()
        if headers["transfer-encoding"]?.lowercased() == "chunked" {
            while true {
                let chunkLine = String(decoding: try line(maximumBytes: 1024), as: UTF8.self)
                guard let number = chunkLine.split(separator: ";", maxSplits: 1).first,
                      let length = Int(number, radix: 16), length >= 0,
                      length <= maximumBodyBytes - responseBody.count else {
                    throw ToolError.message("Bitwarden response body exceeds limit or has an invalid chunk")
                }
                if length == 0 {
                    var trailerBytes = 0
                    while true {
                        let trailer = try line(maximumBytes: 8192)
                        trailerBytes += trailer.count + 2
                        guard trailerBytes <= 65536 else { throw ToolError.message("Bitwarden response trailers exceed limit") }
                        if trailer.isEmpty { break }
                    }
                    break
                }
                responseBody.append(try take(length))
                guard try take(2) == Data([13, 10]) else { throw ToolError.message("Invalid Bitwarden response chunk") }
            }
        } else if let value = headers["content-length"], let length = Int(value),
                  length >= 0, length <= maximumBodyBytes {
            responseBody = try take(length)
        } else {
            throw ToolError.message("Missing or excessive Bitwarden response length")
        }
        return PayloadHTTPResponse(status: status, body: responseBody)
    }
}

func successfulPayloadObject(_ response: PayloadHTTPResponse) throws -> [String: Any] {
    guard (200..<300).contains(response.status),
          let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
          object["success"] as? Bool == true else {
        // Never include an authentication or item body in diagnostic output.
        throw ToolError.message("Bitwarden payload request failed (HTTP \(response.status))")
    }
    return object
}

func executePipedItemOperation(
    _ operation: PipedItemOperation,
    credential: Data,
    processRunner: ProcessRunner,
    payloadRunner: (PipedItemOperation, Data) throws -> Response
) throws -> Response {
    let status = try parseVaultStatus(processRunner(["status"], ["BW_NOINTERACTION": "true"], nil))
    if status.status == "unauthenticated" {
        let login = try processRunner(["login", account, "--quiet"], [:], credential)
        guard login.status == 0 else { return removingPasswordPrompt(from: login) }
    }
    return try payloadRunner(operation, credential)
}

func stopPayloadProcess(_ process: Process) {
    guard process.isRunning else { return }
    process.terminate()
    for _ in 0..<20 {
        if !process.isRunning { return }
        usleep(25_000)
    }
    if process.isRunning { kill(process.processIdentifier, SIGKILL) }
    process.waitUntilExit()
}

private var activePayloadChild: Int32 = 0

private func cancelPayloadChild(_ receivedSignal: Int32) {
    if activePayloadChild > 0 { Darwin.kill(activePayloadChild, SIGKILL) }
    Darwin.signal(receivedSignal, SIG_DFL)
    Darwin.raise(receivedSignal)
}

func runPipedItemOperation(
    _ operation: PipedItemOperation,
    credential: Data,
    executablePath: String = bwPath,
    launchArguments: [String] = ["serve", "--hostname", "fd+connected://0"],
    inheritedEnvironment: [String: String] = ProcessInfo.processInfo.environment,
    timeout: TimeInterval = 45
) throws -> Response {
    var descriptors = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else {
        throw ToolError.message("Unable to create private Bitwarden socket")
    }
    defer { descriptors.filter { $0 >= 0 }.forEach { close($0) } }
    for descriptor in descriptors {
        guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
            throw ToolError.message("Unable to protect private Bitwarden socket")
        }
    }
    let client = try PayloadHTTPClient(descriptor: descriptors[0], timeout: timeout)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executablePath)
    process.arguments = launchArguments
    var environment = inheritedEnvironment
    for name in ["BW_SESSION", "BW_TOUCH_MASTER", "BW_NOINTERACTION"] { environment.removeValue(forKey: name) }
    environment["BW_NOINTERACTION"] = "true"
    process.environment = environment
    process.standardInput = FileHandle(fileDescriptor: descriptors[1], closeOnDealloc: false)
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    var restoreSignals: (() -> Void)?
    defer {
        stopPayloadProcess(process)
        activePayloadChild = 0
        restoreSignals?()
    }
    try process.run()
    activePayloadChild = process.processIdentifier
    let previousInterrupt = Darwin.signal(SIGINT, cancelPayloadChild)
    let previousTermination = Darwin.signal(SIGTERM, cancelPayloadChild)
    restoreSignals = {
        Darwin.signal(SIGINT, previousInterrupt)
        Darwin.signal(SIGTERM, previousTermination)
    }
    close(descriptors[1])
    descriptors[1] = -1
    guard let password = String(data: credential, encoding: .utf8) else {
        throw ToolError.message("Bitwarden credential is not valid UTF-8")
    }
    var unlockBody = try JSONSerialization.data(withJSONObject: ["password": password])
    defer { zeroize(&unlockBody) }
    _ = try successfulPayloadObject(client.request(method: "POST", path: "/unlock", body: unlockBody))
    let result = try successfulPayloadObject(client.request(method: operation.method, path: operation.path, body: operation.body))
    guard let item = result["data"] else { throw ToolError.message("Bitwarden item response has no data") }
    let output = try JSONSerialization.data(withJSONObject: item, options: [.sortedKeys])
    return Response(status: 0, stdout: operation.quiet ? "" : String(decoding: output, as: UTF8.self) + "\n", stderr: "")
}
