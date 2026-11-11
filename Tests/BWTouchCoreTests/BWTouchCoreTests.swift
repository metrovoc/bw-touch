import Darwin
import Foundation
import Security
import XCTest
@testable import BWTouchCore

final class CommandExecutionTests: XCTestCase {
    func testParsesVaultStatus() throws {
        let status = try parseVaultStatus(
            Response(status: 0, stdout: #"{"status":"locked"}"#, stderr: "")
        )
        XCTAssertEqual(status.status, "locked")
    }

    func testMalformedStatusPreservesDiagnostic() {
        assertThrowsMessage(
            try parseVaultStatus(Response(status: 2, stdout: "", stderr: "status failed")),
            contains: "status failed"
        )
    }

    func testPasswordPromptAndANSISequencesAreRemoved() {
        let text = "? Master password: [input is hidden] \u{001B}[37D\u{001B}[37C\nreal warning\n"
        XCTAssertEqual(removingPasswordPrompt(from: text), "real warning")
    }

    func testOnlyExactLockedResponseTriggersRetry() {
        XCTAssertTrue(isLockedResponse(Response(status: 1, stdout: "", stderr: "Vault is locked.\n")))
        XCTAssertFalse(isLockedResponse(Response(status: 1, stdout: "", stderr: "Another vault is locked.")))
        XCTAssertFalse(isLockedResponse(Response(status: 0, stdout: "", stderr: "Vault is locked.")))
    }

    func testOnlyExactItemReadsAreLeasable() {
        XCTAssertEqual(leaseItemID(for: ["get", "item", itemID.uppercased()]), itemID)
        XCTAssertEqual(leaseItemID(for: ["get", "totp", itemID]), itemID)
        XCTAssertNil(leaseItemID(for: ["get", "item", "github"]))
        XCTAssertNil(leaseItemID(for: ["get", "attachment", itemID]))
        XCTAssertNil(leaseItemID(for: ["get", "item", itemID, "--pretty"]))
        XCTAssertNil(leaseItemID(for: ["list", "items", "--search", itemID]))
    }

    func testLockedCommandUnlocksInsideSameProcess() throws {
        var calls: [Invocation] = []
        var authorizationCount = 0
        let response = try executeCommand(
            ["list", "items"],
            authorize: { authorizationCount += 1 },
            credentialReader: { Data("master".utf8) },
            processRunner: { arguments, environment, input in
                calls.append(Invocation(arguments: arguments, environment: environment, standardInput: input))
                if arguments == ["status"] {
                    return Response(status: 0, stdout: #"{"status":"locked"}"#, stderr: "")
                }
                if input == nil {
                    return Response(status: 1, stdout: "", stderr: "Vault is locked.\n")
                }
                return Response(
                    status: 0,
                    stdout: "items",
                    stderr: "? Master password: [input is hidden] \u{001B}[37D\u{001B}[37C"
                )
            }
        )

        XCTAssertEqual(response, Response(status: 0, stdout: "items", stderr: ""))
        XCTAssertEqual(authorizationCount, 1)
        XCTAssertEqual(calls, [
            Invocation(
                arguments: ["list", "items"],
                environment: ["BW_NOINTERACTION": "true"],
                standardInput: nil
            ),
            Invocation(
                arguments: ["list", "items"],
                environment: [:],
                standardInput: Data("master".utf8)
            ),
        ])
    }

    func testSuccessfulCommandDoesNotReadCredential() throws {
        var authorizationCount = 0
        var credentialReadCount = 0
        let response = try executeCommand(
            ["generate"],
            authorize: { authorizationCount += 1 },
            credentialReader: {
                credentialReadCount += 1
                return Data("unused".utf8)
            },
            processRunner: { arguments, _, _ in
                arguments == ["status"]
                    ? Response(status: 0, stdout: #"{"status":"locked"}"#, stderr: "")
                    : Response(status: 0, stdout: "generated", stderr: "")
            }
        )

        XCTAssertEqual(response.stdout, "generated")
        XCTAssertEqual(authorizationCount, 0)
        XCTAssertEqual(credentialReadCount, 0)
    }

    func testUnauthenticatedAccountLogsInThenRunsCommand() throws {
        var calls: [Invocation] = []
        var authorizationCount = 0
        var credentialReadCount = 0
        var loggedIn = false
        let response = try executeCommand(
            ["get", "item", "example"],
            authorize: { authorizationCount += 1 },
            credentialReader: {
                credentialReadCount += 1
                return Data("master".utf8)
            },
            accountReader: { account },
            processRunner: { arguments, environment, input in
                calls.append(Invocation(arguments: arguments, environment: environment, standardInput: input))
                switch arguments {
                case ["status"]:
                    return Response(status: 0, stdout: #"{"status":"unauthenticated"}"#, stderr: "")
                case ["login", account, "--quiet"]:
                    loggedIn = true
                    return Response(status: 0, stdout: "", stderr: "? Master password: [input is hidden]")
                default:
                    if !loggedIn {
                        return Response(status: 1, stdout: "", stderr: "You are not logged in.")
                    }
                    if input == nil {
                        return Response(status: 1, stdout: "", stderr: "Vault is locked.")
                    }
                    return Response(status: 0, stdout: "item", stderr: "")
                }
            }
        )

        XCTAssertEqual(response.stdout, "item")
        XCTAssertEqual(authorizationCount, 2)
        XCTAssertEqual(credentialReadCount, 2)
        XCTAssertEqual(calls[2].arguments, ["login", account, "--quiet"])
        XCTAssertEqual(calls[2].standardInput, Data("master".utf8))
        XCTAssertEqual(calls.last?.standardInput, Data("master".utf8))
    }

    func testLoginFailureIsReturnedWithoutRunningTarget() throws {
        var commands: [[String]] = []
        let response = try executeCommand(
            ["list", "items"],
            authorize: {},
            credentialReader: { Data("master".utf8) },
            accountReader: { account },
            processRunner: { arguments, _, _ in
                commands.append(arguments)
                if arguments == ["status"] {
                    return Response(status: 0, stdout: #"{"status":"unauthenticated"}"#, stderr: "")
                }
                return Response(status: 1, stdout: "", stderr: "two-step login required")
            }
        )

        XCTAssertEqual(response.status, 1)
        XCTAssertTrue(response.stderr.contains("two-step"))
        XCTAssertEqual(commands, [
            ["list", "items"],
            ["status"],
            ["login", account, "--quiet"],
        ])
    }

    func testUnrelatedFailureIsNotRetried() throws {
        var authorizationCount = 0
        var commandCount = 0
        let response = try executeCommand(
            ["get", "item", "missing"],
            authorize: { authorizationCount += 1 },
            credentialReader: { Data("master".utf8) },
            processRunner: { arguments, _, _ in
                if arguments == ["status"] {
                    return Response(status: 0, stdout: #"{"status":"locked"}"#, stderr: "")
                }
                commandCount += 1
                return Response(status: 1, stdout: "", stderr: "Not found.")
            }
        )

        XCTAssertEqual(response.stderr, "Not found.")
        XCTAssertEqual(commandCount, 1)
        XCTAssertEqual(authorizationCount, 0)
    }

    func testZeroizeClearsCredentialBytes() {
        var credential = Data("master".utf8)
        zeroize(&credential)
        XCTAssertTrue(credential.isEmpty)
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

    func testRejectedSocketPathDoesNotLeakDescriptor() throws {
        let available = dup(STDIN_FILENO)
        XCTAssertGreaterThanOrEqual(available, 0)
        close(available)

        assertThrowsMessage(
            try connectSocket(path: "/tmp/" + String(repeating: "a", count: 200)),
            contains: "too long"
        )

        XCTAssertEqual(fcntl(available, F_GETFD), -1)
        XCTAssertEqual(errno, EBADF)
    }

    func testProductionSocketPathIsStableAcrossTemporaryDirectories() {
        XCTAssertTrue(socketPath.hasSuffix("/Library/Caches/bw-touch/agent.sock"))
        XCTAssertFalse(socketPath.contains(FileManager.default.temporaryDirectory.path + "/bw-touch-"))
    }

    func testRuntimeDirectoryIsCreatedUserOnly() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("bwt-runtime-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }

        try prepareRuntimeDirectory(at: directory)

        var metadata = stat()
        XCTAssertEqual(lstat(directory.path, &metadata), 0)
        XCTAssertEqual(metadata.st_uid, getuid())
        XCTAssertEqual(metadata.st_mode & 0o777, 0o700)
    }

    func testAgentLaunchUsesGraphicalUserBootstrap() {
        XCTAssertEqual(
            agentLaunchArguments(executable: "/usr/local/bin/bw-touch", userID: 42),
            ["asuser", "42", "/usr/local/bin/bw-touch", "--daemon"]
        )
    }

    func testAgentLockRejectsSecondOwner() throws {
        let path = "/tmp/bwt-lock-\(UUID().uuidString)"
        defer { unlink(path) }
        let first = try acquireAgentLock(path: path)
        defer { close(first) }

        assertThrowsMessage(try acquireAgentLock(path: path), contains: "already running")
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

    func testClientSurvivesServerDisconnectingBeforeRequest() throws {
        let path = temporarySocketPath()
        let server = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(server, 0)
        defer { close(server); unlink(path) }
        var address = try makeAddress(path: path)
        XCTAssertEqual(withSocketAddress(&address) { Darwin.bind(server, $0, $1) }, 0)
        XCTAssertEqual(listen(server, 1), 0)

        let client = try connectSocket(path: path)
        defer { close(client) }
        let accepted = accept(server, nil, nil)
        XCTAssertGreaterThanOrEqual(accepted, 0)
        close(accepted)

        assertThrowsMessage(try writeAll(client, data: Data("request".utf8)), contains: "write failed")
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

    func testProcessRunnerWritesStandardInputWithoutPuttingItInArguments() throws {
        let input = Data("pipe-only-value".utf8)
        let response = try runProcess(
            executablePath: "/bin/sh",
            arguments: ["-c", "IFS= read -r value; printf %s \"$value\""],
            standardInput: input
        )

        XCTAssertEqual(response.status, 0)
        XCTAssertEqual(response.stdout, "pipe-only-value")
    }

    func testProcessRunnerClosesUnusedStandardInput() throws {
        let response = try runProcess(
            executablePath: "/bin/sh",
            arguments: ["-c", "if IFS= read -r value; then exit 1; else printf eof; fi"]
        )
        XCTAssertEqual(response.status, 0)
        XCTAssertEqual(response.stdout, "eof")
    }

    func testProcessRunnerSurvivesChildClosingStandardInput() throws {
        let response = try runProcess(
            executablePath: "/bin/sh",
            arguments: ["-c", "exec 0<&-; printf diagnostic >&2; exit 9"],
            standardInput: Data(repeating: 0x61, count: 1024 * 1024)
        )

        XCTAssertEqual(response.status, 9)
        XCTAssertEqual(response.stderr, "diagnostic")
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
    func testOnlyLockAndLogoutEndAuthorization() {
        for arguments in [
            ["lock"], ["logout"], ["--quiet", "lock"], ["--response", "logout"],
            ["--pretty", "--raw", "--cleanexit", "--nointeraction", "lock", "--quiet"],
            ["--session", "synthetic-session", "lock"], ["--session=synthetic-session", "logout"],
            ["--", "lock"], ["lock", "--"], ["--quiet", "--", "logout"],
        ] {
            XCTAssertTrue(isSessionEndingCommand(arguments), "Expected session-ending command: \(arguments)")
        }
        for arguments in [
            [], ["get", "item", "lock"], ["--session", "lock"], ["--session=logout"],
            ["--session"], ["--unknown", "lock"], ["lock", "--unknown"],
            ["--help", "lock"], ["lock", "--help"], ["logout", "-h"],
            ["--"], ["--", "--quiet", "lock"], ["lock", "--", "--quiet"],
        ] {
            XCTAssertFalse(isSessionEndingCommand(arguments), "Unexpected session-ending command: \(arguments)")
        }
    }

    func testDisconnectedLockAndLogoutStillEndAuthorization() throws {
        for command in [["lock"], ["lock", "--quiet"], ["logout"], ["--quiet", "lock"], ["--response", "logout"]] {
            let path = temporarySocketPath()
            let terminationStarted = DispatchSemaphore(value: 0)
            let allowTermination = DispatchSemaphore(value: 0)
            var terminationCount = 0
            let recorder = InvocationRecorder { arguments, environment, input in
                if arguments == command || arguments == ["lock"] {
                    terminationCount += 1
                    if terminationCount == 1 {
                        terminationStarted.signal()
                        _ = allowTermination.wait(timeout: .now() + 2)
                    }
                    return Response(status: 0, stdout: "", stderr: "")
                }
                if environment["BW_NOINTERACTION"] == "true" && input == nil {
                    return Response(status: 1, stdout: "", stderr: "Vault is locked.")
                }
                return Response(status: 0, stdout: "synthetic item", stderr: "")
            }
            let finished = startDaemon(path: path, timeout: 5, recorder: recorder)
            defer { cleanupDaemon(path: path) }
            waitForSocket(path)
            _ = try sendRequest(["get", "item", itemID], path: path, spawn: {})

            let client = try connectSocket(path: path)
            try writeAll(client, data: JSONEncoder().encode(Request(arguments: command)))
            shutdown(client, SHUT_WR)
            XCTAssertEqual(terminationStarted.wait(timeout: .now() + 2), .success)
            close(client)
            allowTermination.signal()

            wait(for: [finished], timeout: 1)
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
            XCTAssertEqual(recorder.snapshot().last?.arguments, command)
        }
    }

    func testStalledClientsDoNotBlockFollowingRequests() throws {
        for stallsOutput in [false, true] {
            let path = temporarySocketPath()
            let recorder = InvocationRecorder { arguments, _, _ in
                Response(status: 0,
                         stdout: arguments == ["generate"] ? String(repeating: "x", count: 4 * 1024 * 1024) : "ok",
                         stderr: "")
            }
            let finished = startDaemon(path: path, timeout: 3, clientTimeout: 0.1, recorder: recorder)
            defer { cleanupDaemon(path: path) }
            waitForSocket(path)

            let stalled = try connectSocket(path: path)
            defer { close(stalled) }
            if stallsOutput {
                try writeAll(stalled, data: JSONEncoder().encode(Request(arguments: ["generate"])))
                shutdown(stalled, SHUT_WR)
            } else {
                try writeAll(stalled, data: Data("{".utf8))
            }
            let releaseClient = expectation(description: "release stalled client")
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.8) {
                shutdown(stalled, SHUT_RDWR)
                releaseClient.fulfill()
            }
            defer { wait(for: [releaseClient], timeout: 2) }

            let start = Date()
            XCTAssertEqual(try sendRequest(["status"], path: path, spawn: {}).stdout, "ok")
            XCTAssertLessThan(Date().timeIntervalSince(start), 0.6)
            _ = try sendRequest(["lock"], path: path, spawn: {})
            wait(for: [finished], timeout: 2)
        }
    }

    func testAuthorizationWindowStartsWhenAuthenticationCompletes() throws {
        let path = temporarySocketPath()
        var authorizationCount = 0
        var credentialReads = 0
        let finished = startDaemon(
            path: path,
            timeout: 0.2,
            authenticator: {
                authorizationCount += 1
                usleep(300_000)
            },
            credentialReader: {
                credentialReads += 1
                if credentialReads == 1 { throw ToolError.message("Synthetic credential read failure") }
                return Data("master".utf8)
            },
            recorder: lockedVaultRecorder()
        )
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        XCTAssertEqual(try sendRequest(["list", "items"], path: path, spawn: {}).status, 1)
        XCTAssertEqual(try sendRequest(["list", "items"], path: path, spawn: {}).status, 0)
        XCTAssertEqual(authorizationCount, 1)
        _ = try sendRequest(["lock"], path: path, spawn: {})
        wait(for: [finished], timeout: 2)
    }

    func testRequestCompletedAfterIdleExpiryRequiresNewAuthorization() throws {
        let path = temporarySocketPath()
        var authorizationCount = 0
        let recorder = lockedVaultRecorder()
        let finished = startDaemon(
            path: path,
            timeout: 0.2,
            leaseDuration: 5,
            authenticator: { authorizationCount += 1 },
            recorder: recorder
        )
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)
        _ = try sendRequest(["get", "item", itemID], path: path, spawn: {})

        let client = try connectSocket(path: path)
        defer { close(client) }
        try writeAll(client, data: JSONEncoder().encode(Request(arguments: ["get", "item", otherItemID])))
        usleep(450_000)
        shutdown(client, SHUT_WR)
        let response = try JSONDecoder().decode(Response.self, from: readAll(client))
        XCTAssertEqual(response.status, 0)
        XCTAssertEqual(authorizationCount, 2)

        _ = try sendRequest(["lock"], path: path, spawn: {})
        wait(for: [finished], timeout: 2)
    }

    func testDaemonReusesAuthorizationAndReadsCredentialPerLockedCommand() throws {
        let path = temporarySocketPath()
        var authorizationCount = 0
        var credentialReadCount = 0
        let recorder = lockedVaultRecorder()
        let finished = startDaemon(
            path: path,
            timeout: 5,
            authenticator: { authorizationCount += 1 },
            credentialReader: {
                credentialReadCount += 1
                return Data("master".utf8)
            },
            recorder: recorder
        )
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        XCTAssertEqual(try sendRequest(["list", "items"], path: path, spawn: {}).stdout, "list items")
        XCTAssertEqual(try sendRequest(["get", "item", "example"], path: path, spawn: {}).stdout, "get item example")
        XCTAssertEqual(authorizationCount, 1)
        XCTAssertEqual(credentialReadCount, 2)

        let credentialInvocations = recorder.snapshot().filter { $0.standardInput != nil }
        XCTAssertEqual(credentialInvocations.count, 2)
        XCTAssertTrue(credentialInvocations.allSatisfy { $0.standardInput == Data("master".utf8) })
        XCTAssertTrue(recorder.snapshot().allSatisfy { $0.environment["BW_SESSION"] == nil })

        XCTAssertEqual(try sendRequest(["lock"], path: path, spawn: {}).status, 0)
        wait(for: [finished], timeout: 2)
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        XCTAssertEqual(recorder.snapshot().last?.arguments, ["lock"])
    }

    func testDaemonSocketIsUserOnly() throws {
        let path = temporarySocketPath()
        let recorder = InvocationRecorder()
        let finished = startDaemon(path: path, timeout: 5, recorder: recorder)
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
        let finished = startDaemon(path: path, timeout: 5, recorder: recorder)
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

    func testClientThatDisconnectsDoesNotStopDaemon() throws {
        let path = temporarySocketPath()
        let recorder = InvocationRecorder()
        let finished = startDaemon(path: path, timeout: 5, recorder: recorder)
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        let abandoned = try connectSocket(path: path)
        try writeAll(abandoned, data: JSONEncoder().encode(Request(arguments: ["generate"])))
        close(abandoned)

        XCTAssertEqual(try sendRequest(["status"], path: path, spawn: {}).status, 0)
        _ = try sendRequest(["lock"], path: path, spawn: {})
        wait(for: [finished], timeout: 2)
    }

    func testIdleTimeoutLocksAndRemovesSocket() throws {
        let path = temporarySocketPath()
        let recorder = lockedVaultRecorder()
        let finished = startDaemon(
            path: path,
            timeout: 0.15,
            authenticator: {},
            credentialReader: { Data("master".utf8) },
            recorder: recorder
        )
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        _ = try sendRequest(["list", "items"], path: path, spawn: {})
        wait(for: [finished], timeout: 2)

        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        XCTAssertEqual(recorder.snapshot().last?.arguments, ["lock"])
    }

    func testItemReadInWindowStaysAvailableAfterWindowCloses() throws {
        let path = temporarySocketPath()
        var authorizationCount = 0
        let recorder = lockedVaultRecorder()
        let finished = startDaemon(
            path: path,
            timeout: 0.2,
            leaseDuration: 5,
            authenticator: { authorizationCount += 1 },
            recorder: recorder
        )
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        let read = ["get", "item", itemID]
        XCTAssertEqual(try sendRequest(read, path: path, spawn: {}).stdout, read.joined(separator: " "))
        usleep(400_000)
        XCTAssertEqual(recorder.snapshot().last?.arguments, ["lock"])

        XCTAssertEqual(try sendRequest(read, path: path, spawn: {}).stdout, read.joined(separator: " "))
        XCTAssertEqual(try sendRequest(["get", "totp", itemID.uppercased()], path: path, spawn: {}).status, 0)
        XCTAssertEqual(recorder.snapshot().last?.standardInput, Data("master".utf8))
        XCTAssertEqual(authorizationCount, 1)

        XCTAssertEqual(try sendRequest(["get", "item", otherItemID], path: path, spawn: {}).status, 0)
        XCTAssertEqual(authorizationCount, 2)

        _ = try sendRequest(["lock"], path: path, spawn: {})
        wait(for: [finished], timeout: 2)
    }

    func testLeaseReadsDoNotExtendLeaseAndDaemonExitsAfterLastLease() throws {
        let path = temporarySocketPath()
        var authorizationCount = 0
        let recorder = lockedVaultRecorder()
        let start = Date()
        let finished = startDaemon(
            path: path,
            timeout: 0.2,
            leaseDuration: 1,
            authenticator: { authorizationCount += 1 },
            recorder: recorder
        )
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        XCTAssertEqual(try sendRequest(["get", "item", itemID], path: path, spawn: {}).status, 0)
        usleep(600_000)
        XCTAssertEqual(try sendRequest(["get", "item", itemID], path: path, spawn: {}).status, 0)

        wait(for: [finished], timeout: 3)
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.4)
        XCTAssertEqual(authorizationCount, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }

    func testLockDoesNotAuthenticateOrReadCredential() throws {
        let path = temporarySocketPath()
        let recorder = InvocationRecorder()
        var authorizationCount = 0
        var credentialReadCount = 0
        let finished = startDaemon(
            path: path,
            timeout: 5,
            authenticator: { authorizationCount += 1 },
            credentialReader: {
                credentialReadCount += 1
                return Data("master".utf8)
            },
            recorder: recorder
        )
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        _ = try sendRequest(["lock"], path: path, spawn: {})
        wait(for: [finished], timeout: 2)
        XCTAssertEqual(authorizationCount, 0)
        XCTAssertEqual(credentialReadCount, 0)
    }

    func testSecondDaemonCannotReplaceFirstSocket() throws {
        let path = temporarySocketPath()
        let recorder = InvocationRecorder()
        let finished = startDaemon(path: path, timeout: 5, recorder: recorder)
        defer { cleanupDaemon(path: path) }
        waitForSocket(path)

        assertThrowsMessage(
            try runDaemon(
                path: path,
                lockFilePath: path + ".lock",
                timeout: 0.1,
                prepare: {},
                authenticator: {},
                credentialReader: { Data("master".utf8) },
                processRunner: recorder.run
            ),
            contains: "already running"
        )

        XCTAssertEqual(try sendRequest(["status"], path: path, spawn: {}).status, 0)
        _ = try sendRequest(["lock"], path: path, spawn: {})
        wait(for: [finished], timeout: 2)
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

final class BWLocationTests: XCTestCase {
    func testLocatesBWOnSearchPathBeforeFallbacks() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let onPath = root.appendingPathComponent("path")
        let fallback = root.appendingPathComponent("fallback")
        for directory in [onPath, fallback] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let binary = directory.appendingPathComponent("bw")
            FileManager.default.createFile(atPath: binary.path, contents: Data(),
                                           attributes: [.posixPermissions: 0o755])
        }
        defer { try? FileManager.default.removeItem(at: root) }

        XCTAssertEqual(
            locateBW(searchPath: "relative:\(root.path)/missing:\(onPath.path)", fallbackDirectories: [fallback.path]),
            onPath.appendingPathComponent("bw").path
        )
        XCTAssertEqual(
            locateBW(searchPath: nil, fallbackDirectories: [fallback.path]),
            fallback.appendingPathComponent("bw").path
        )
        XCTAssertEqual(locateBW(searchPath: "\(root.path)/missing", fallbackDirectories: []), "bw")
    }
}

private let account = "user@example.com"
private let itemID = "0f8fad5b-d9cb-469f-a165-70867728950e"
private let otherItemID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"

private struct Invocation: Equatable {
    let arguments: [String]
    let environment: [String: String]
    let standardInput: Data?
}

private final class InvocationRecorder {
    typealias Handler = ([String], [String: String], Data?) -> Response

    private let lock = NSLock()
    private var invocations: [Invocation] = []
    private let handler: Handler

    init(handler: @escaping Handler = { arguments, _, _ in
        Response(status: 0, stdout: arguments.joined(separator: " "), stderr: "")
    }) {
        self.handler = handler
    }

    func run(arguments: [String], environment: [String: String], standardInput: Data?) -> Response {
        lock.lock()
        invocations.append(
            Invocation(arguments: arguments, environment: environment, standardInput: standardInput)
        )
        lock.unlock()
        return handler(arguments, environment, standardInput)
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
        leaseDuration: TimeInterval = leaseTTL,
        clientTimeout: TimeInterval = 5,
        authenticator: @escaping () throws -> Void = {},
        credentialReader: @escaping () throws -> Data = { Data("master".utf8) },
        recorder: InvocationRecorder
    ) -> XCTestExpectation {
        let finished = expectation(description: "daemon finished")
        DispatchQueue.global().async {
            defer { finished.fulfill() }
            do {
                try runDaemon(
                    path: path,
                    lockFilePath: path + ".lock",
                    timeout: timeout,
                    leaseDuration: leaseDuration,
                    clientTimeout: clientTimeout,
                    prepare: {},
                    authenticator: authenticator,
                    credentialReader: credentialReader,
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
        unlink(path + ".lock")
    }
}

private func lockedVaultRecorder() -> InvocationRecorder {
    InvocationRecorder { arguments, environment, standardInput in
        if arguments == ["status"] {
            return Response(status: 0, stdout: #"{"status":"locked"}"#, stderr: "")
        }
        if arguments == ["lock"] {
            return Response(status: 0, stdout: "locked", stderr: "")
        }
        if environment["BW_NOINTERACTION"] == "true" && standardInput == nil {
            return Response(status: 1, stdout: "", stderr: "Vault is locked.")
        }
        return Response(status: 0, stdout: arguments.joined(separator: " "), stderr: "")
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
