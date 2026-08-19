import Darwin
import Foundation
import Security
import XCTest
@testable import BWTouchCore

final class SessionTests: XCTestCase {
    func testSessionResponseTrimsWhitespace() throws {
        let response = Response(status: 0, stdout: "  session-token\n", stderr: "")
        XCTAssertEqual(try sessionFromResponse(response, action: "unlock"), "session-token")
    }

    func testSessionResponseUsesStderrOnFailure() {
        assertThrowsMessage(
            try sessionFromResponse(Response(status: 1, stdout: "", stderr: "server rejected\n"), action: "login"),
            contains: "server rejected"
        )
    }

    func testSessionResponseBuildsFallbackFailure() {
        assertThrowsMessage(
            try sessionFromResponse(Response(status: 1, stdout: "", stderr: ""), action: "unlock"),
            contains: "Bitwarden unlock failed"
        )
    }

    func testSessionResponseRejectsEmptyToken() {
        assertThrowsMessage(
            try sessionFromResponse(Response(status: 0, stdout: " \n", stderr: ""), action: "login"),
            contains: "empty session"
        )
    }

    func testUnauthenticatedStatusLogsIn() throws {
        var calls: [Invocation] = []
        let session = try createSession(
            credentialReader: { "master" },
            processRunner: { arguments, environment in
                calls.append(Invocation(arguments: arguments, environment: environment))
                if arguments == ["status"] {
                    return Response(status: 0, stdout: #"{"status":"unauthenticated"}"#, stderr: "")
                }
                return Response(status: 0, stdout: "login-session\n", stderr: "")
            }
        )

        XCTAssertEqual(session, "login-session")
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(calls[0], Invocation(arguments: ["status"], environment: [:]))
        XCTAssertEqual(
            calls[1],
            Invocation(
                arguments: ["login", account, "--passwordenv", "BW_TOUCH_MASTER", "--raw"],
                environment: ["BW_TOUCH_MASTER": "master"]
            )
        )
    }

    func testLockedStatusUnlocks() throws {
        var calls: [Invocation] = []
        let session = try createSession(
            credentialReader: { "master" },
            processRunner: { arguments, environment in
                calls.append(Invocation(arguments: arguments, environment: environment))
                if arguments == ["status"] {
                    return Response(status: 0, stdout: #"{"status":"locked"}"#, stderr: "")
                }
                return Response(status: 0, stdout: "unlock-session", stderr: "")
            }
        )

        XCTAssertEqual(session, "unlock-session")
        XCTAssertEqual(
            calls.last,
            Invocation(
                arguments: ["unlock", "--passwordenv", "BW_TOUCH_MASTER", "--raw"],
                environment: ["BW_TOUCH_MASTER": "master"]
            )
        )
    }

    func testUnlockedStatusRefreshesSessionByUnlocking() throws {
        var commands: [[String]] = []
        _ = try createSession(
            credentialReader: { "master" },
            processRunner: { arguments, _ in
                commands.append(arguments)
                if arguments == ["status"] {
                    return Response(status: 0, stdout: #"{"status":"unlocked"}"#, stderr: "")
                }
                return Response(status: 0, stdout: "refreshed", stderr: "")
            }
        )
        XCTAssertEqual(commands, [
            ["status"],
            ["unlock", "--passwordenv", "BW_TOUCH_MASTER", "--raw"],
        ])
    }

    func testMalformedStatusFailsBeforeLogin() {
        var callCount = 0
        assertThrowsMessage(
            try createSession(
                credentialReader: { "master" },
                processRunner: { _, _ in
                    callCount += 1
                    return Response(status: 0, stdout: "not-json", stderr: "")
                }
            ),
            contains: "Unable to read Bitwarden status"
        )
        XCTAssertEqual(callCount, 1)
    }

    func testStatusFailurePreservesDiagnostic() {
        assertThrowsMessage(
            try createSession(
                credentialReader: { "master" },
                processRunner: { _, _ in Response(status: 2, stdout: "", stderr: "status failed") }
            ),
            contains: "status failed"
        )
    }

    func testLoginFailurePreservesDiagnostic() {
        assertThrowsMessage(
            try createSession(
                credentialReader: { "master" },
                processRunner: { arguments, _ in
                    arguments == ["status"]
                        ? Response(status: 0, stdout: #"{"status":"unauthenticated"}"#, stderr: "")
                        : Response(status: 1, stdout: "", stderr: "two-step login required")
                }
            ),
            contains: "two-step login required"
        )
    }
}

final class PathAndSocketTests: XCTestCase {
    func testResolvedExecutablePathResolvesSymlink() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let executable = directory.appendingPathComponent("real")
        let link = directory.appendingPathComponent("bw-touch")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        XCTAssertTrue(FileManager.default.createFile(atPath: executable.path, contents: Data()))
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: executable)

        XCTAssertEqual(try resolvedExecutablePath(link), executable.path)
    }

    func testResolvedExecutablePathRejectsMissingURL() {
        assertThrowsMessage(try resolvedExecutablePath(nil), contains: "Unable to resolve")
    }

    func testRequestCodableRoundTripPreservesArguments() throws {
        let request = Request(arguments: ["get", "pāss word", "换行\n值"])
        let decoded = try JSONDecoder().decode(Request.self, from: JSONEncoder().encode(request))
        XCTAssertEqual(decoded.arguments, request.arguments)
    }

    func testResponseCodableRoundTripPreservesStreams() throws {
        let response = Response(status: 7, stdout: "out\u{0}put", stderr: "错误")
        let decoded = try JSONDecoder().decode(Response.self, from: JSONEncoder().encode(response))
        XCTAssertEqual(decoded.status, response.status)
        XCTAssertEqual(decoded.stdout, response.stdout)
        XCTAssertEqual(decoded.stderr, response.stderr)
    }

    func testUnixSocketRejectsOverlongPath() {
        assertThrowsMessage(try makeAddress(path: "/tmp/" + String(repeating: "a", count: 200)), contains: "too long")
    }

    func testSocketReadWriteHandlesLargePayload() throws {
        var descriptors = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors), 0)
        defer { descriptors.forEach { close($0) } }
        let expected = Data(repeating: 0x5a, count: 256 * 1024)
        let finished = expectation(description: "writer finished")
        DispatchQueue.global().async {
            defer { finished.fulfill() }
            try? writeAll(descriptors[0], data: expected)
            shutdown(descriptors[0], SHUT_WR)
        }
        XCTAssertEqual(try readAll(descriptors[1]), expected)
        wait(for: [finished], timeout: 2)
    }

    func testSocketReadReturnsEmptyAtEOF() throws {
        var descriptors = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors), 0)
        defer { descriptors.forEach { close($0) } }
        shutdown(descriptors[0], SHUT_WR)
        XCTAssertEqual(try readAll(descriptors[1]), Data())
    }
}

final class ProcessRunnerTests: XCTestCase {
    func testProcessRunnerCapturesOutputErrorAndExitStatus() throws {
        let response = try runProcess(
            executablePath: "/bin/sh",
            arguments: ["-c", "printf output; printf diagnostic >&2; exit 7"]
        )
        XCTAssertEqual(response.status, 7)
        XCTAssertEqual(response.stdout, "output")
        XCTAssertEqual(response.stderr, "diagnostic")
    }

    func testProcessRunnerInjectsEnvironmentIntoChildOnly() throws {
        XCTAssertNil(ProcessInfo.processInfo.environment["BW_TOUCH_TEST_VALUE"])
        let response = try runProcess(
            executablePath: "/bin/sh",
            arguments: ["-c", "printf %s \"$BW_TOUCH_TEST_VALUE\""],
            extraEnvironment: ["BW_TOUCH_TEST_VALUE": "scoped-value"]
        )
        XCTAssertEqual(response.status, 0)
        XCTAssertEqual(response.stdout, "scoped-value")
        XCTAssertNil(ProcessInfo.processInfo.environment["BW_TOUCH_TEST_VALUE"])
    }

    func testProcessRunnerDrainsLargeOutputAndErrorConcurrently() throws {
        let response = try runProcess(
            executablePath: "/bin/sh",
            arguments: [
                "-c",
                "i=0; while [ $i -lt 8192 ]; do printf 0123456789abcdef; printf fedcba9876543210 >&2; i=$((i+1)); done",
            ]
        )
        XCTAssertEqual(response.status, 0)
        XCTAssertEqual(response.stdout.utf8.count, 131_072)
        XCTAssertEqual(response.stderr.utf8.count, 131_072)
    }
}

final class DaemonTests: XCTestCase {
    func testDaemonReusesSessionAndLocksCleanly() throws {
        let path = temporarySocketPath()
        let recorder = InvocationRecorder()
        var sessionCount = 0
        let finished = startDaemon(
            path: path,
            timeout: 5,
            sessionFactory: {
                sessionCount += 1
                return "memory-session"
            },
            recorder: recorder
        )
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        XCTAssertEqual(try sendRequest(["status"], path: path, spawn: {}).stdout, "status")
        XCTAssertEqual(try sendRequest(["list", "items"], path: path, spawn: {}).stdout, "list items")
        XCTAssertEqual(sessionCount, 1)
        let invocations = recorder.snapshot()
        XCTAssertEqual(invocations.count, 2)
        XCTAssertEqual(invocations.first?.environment, ["BW_SESSION": "memory-session"])
        XCTAssertEqual(invocations.last?.environment, ["BW_SESSION": "memory-session"])

        XCTAssertEqual(try sendRequest(["lock"], path: path, spawn: {}).status, 0)
        wait(for: [finished], timeout: 2)
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        XCTAssertEqual(recorder.snapshot().last?.arguments, ["lock"])
    }

    func testDaemonSocketIsUserOnly() throws {
        let path = temporarySocketPath()
        let recorder = InvocationRecorder()
        let finished = startDaemon(path: path, timeout: 5, sessionFactory: { "session" }, recorder: recorder)
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        var metadata = stat()
        XCTAssertEqual(lstat(path, &metadata), 0)
        XCTAssertEqual(metadata.st_mode & 0o777, 0o600)

        _ = try sendRequest(["lock"], path: path, spawn: {})
        wait(for: [finished], timeout: 2)
    }

    func testMalformedRequestReturnsErrorAndDaemonContinues() throws {
        let path = temporarySocketPath()
        let recorder = InvocationRecorder()
        let finished = startDaemon(path: path, timeout: 5, sessionFactory: { "session" }, recorder: recorder)
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        let client = try connectSocket(path: path)
        try writeAll(client, data: Data("{".utf8))
        shutdown(client, SHUT_WR)
        let response = try JSONDecoder().decode(Response.self, from: readAll(client))
        close(client)
        XCTAssertEqual(response.status, 1)
        XCTAssertFalse(response.stderr.isEmpty)

        XCTAssertEqual(try sendRequest(["status"], path: path, spawn: {}).status, 0)
        _ = try sendRequest(["lock"], path: path, spawn: {})
        wait(for: [finished], timeout: 2)
    }

    func testIdleTimeoutLocksAndRemovesSocket() throws {
        let path = temporarySocketPath()
        let recorder = InvocationRecorder()
        let finished = startDaemon(path: path, timeout: 0.15, sessionFactory: { "session" }, recorder: recorder)
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        _ = try sendRequest(["status"], path: path, spawn: {})
        wait(for: [finished], timeout: 2)

        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        XCTAssertEqual(recorder.snapshot().last?.arguments, ["lock"])
    }

    func testLockDoesNotCreateSession() throws {
        let path = temporarySocketPath()
        let recorder = InvocationRecorder()
        var sessionCount = 0
        let finished = startDaemon(
            path: path,
            timeout: 5,
            sessionFactory: {
                sessionCount += 1
                return "session"
            },
            recorder: recorder
        )
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        _ = try sendRequest(["lock"], path: path, spawn: {})
        wait(for: [finished], timeout: 2)
        XCTAssertEqual(sessionCount, 0)
    }
}

final class KeychainIntegrationTests: XCTestCase {
    private let service = "bitwarden.cli-keychain-test.\(UUID().uuidString)"
    private let account = "bw-touch-tests"

    override func tearDown() {
        deleteIdentity(service: service, account: account)
        super.tearDown()
    }

    func testKeychainACLSetupReadAndCleanup() throws {
        deleteIdentity(service: service, account: account)
        try selfTestKeychain(service: service, account: account)
        XCTAssertEqual(identityStatus(service: service, account: account), errSecItemNotFound)
    }

    func testKeychainSelfTestPreservesExistingIdentity() throws {
        let query = keychainQuery(service: service, account: account)
        var item = query
        item[kSecValueData as String] = Data("existing-non-secret".utf8)
        XCTAssertEqual(SecItemAdd(item as CFDictionary, nil), errSecSuccess)

        assertThrowsMessage(
            try selfTestKeychain(service: service, account: account),
            contains: "already exists"
        )
        XCTAssertEqual(identityStatus(service: service, account: account), errSecSuccess)
    }
}

private struct Invocation: Equatable {
    let arguments: [String]
    let environment: [String: String]
}

private final class InvocationRecorder {
    private let lock = NSLock()
    private var invocations: [Invocation] = []

    func run(arguments: [String], environment: [String: String]) -> Response {
        lock.lock()
        invocations.append(Invocation(arguments: arguments, environment: environment))
        lock.unlock()
        return Response(status: 0, stdout: arguments.joined(separator: " "), stderr: "")
    }

    func snapshot() -> [Invocation] {
        lock.lock()
        defer { lock.unlock() }
        return invocations
    }
}

private extension XCTestCase {
    func assertThrowsMessage<T>(
        _ expression: @autoclosure () throws -> T,
        contains expected: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        do {
            _ = try expression()
            XCTFail("Expected an error containing \(expected)", file: file, line: line)
        } catch {
            XCTAssertTrue("\(error)".contains(expected), "Unexpected error: \(error)", file: file, line: line)
        }
    }

    func temporarySocketPath() -> String {
        "/tmp/bwt-\(UUID().uuidString.prefix(12)).sock"
    }

    func waitForSocket(_ path: String, file: StaticString = #filePath, line: UInt = #line) {
        for _ in 0..<200 {
            if FileManager.default.fileExists(atPath: path) { return }
            usleep(10_000)
        }
        XCTFail("Socket did not appear: \(path)", file: file, line: line)
    }

    func startDaemon(
        path: String,
        timeout: TimeInterval,
        sessionFactory: @escaping () throws -> String,
        recorder: InvocationRecorder
    ) -> XCTestExpectation {
        let finished = expectation(description: "daemon finished")
        DispatchQueue.global().async {
            defer { finished.fulfill() }
            do {
                try runDaemon(
                    path: path,
                    timeout: timeout,
                    sessionFactory: sessionFactory,
                    processRunner: recorder.run
                )
            } catch {
                XCTFail("Daemon failed: \(error)")
            }
        }
        return finished
    }

    func cleanupDaemon(path: String) {
        if FileManager.default.fileExists(atPath: path) {
            _ = try? sendRequest(["lock"], path: path, spawn: {})
        }
        unlink(path)
    }
}

private func keychainQuery(service: String, account: String) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
}

private func identityStatus(service: String, account: String) -> OSStatus {
    SecItemCopyMatching(keychainQuery(service: service, account: account) as CFDictionary, nil)
}

private func deleteIdentity(service: String, account: String) {
    SecItemDelete(keychainQuery(service: service, account: account) as CFDictionary)
}
