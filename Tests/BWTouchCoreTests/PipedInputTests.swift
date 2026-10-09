import Darwin
import Foundation
import XCTest
@testable import BWTouchCore

final class PipedInputTests: XCTestCase {
    private let item = Data(#"{"type":2,"name":"synthetic item","secureNote":{"type":0}}"#.utf8)

    func testOnlyNoninteractiveCreateAndEditReadInput() throws {
        for command in [["login"], ["unlock"], ["get", "item", "id"], ["status"]] {
            XCTAssertNil(try commandInput(arguments: command, isTerminal: false) {
                XCTFail("Unrelated commands must not consume stdin"); return Data()
            })
        }
        XCTAssertNil(try commandInput(arguments: ["create", "item"], isTerminal: true) {
            XCTFail("Terminal stdin must not be consumed"); return Data()
        })
        var chunks = [Data("abc".utf8), Data("\n".utf8), Data()]
        XCTAssertEqual(try commandInput(arguments: ["create", "item"], isTerminal: false) {
            chunks.removeFirst()
        }, Data("abc\n".utf8))
        XCTAssertThrowsError(try commandInput(arguments: ["edit", "item"], isTerminal: false) {
            Data(repeating: 65, count: maximumPipedInputBytes + 1)
        })
    }

    func testOperationsValidatePayloadAndArguments() throws {
        let input = Data((item.base64EncodedString() + "\n").utf8)
        let create = try PipedItemOperation(arguments: ["create", "item", "--quiet"], encodedInput: input)
        XCTAssertEqual(create.method, "POST")
        XCTAssertEqual(create.path, "/object/item")
        XCTAssertTrue(create.quiet)
        let identifier = "01234567-89ab-cdef-0123-456789abcdef"
        let edit = try PipedItemOperation(arguments: ["edit", "item", identifier, "--raw"], encodedInput: input)
        XCTAssertEqual(edit.method, "PUT")
        XCTAssertEqual(edit.path, "/object/item/" + identifier)
        let decoded = try JSONSerialization.jsonObject(with: edit.body) as? [String: Any]
        XCTAssertEqual(decoded?["name"] as? String, "synthetic item")
        for arguments in [["login"], ["create", "folder"], ["edit", "item", "../unlock"],
                          ["create", "item", "--session", "value"]] {
            XCTAssertThrowsError(try PipedItemOperation(arguments: arguments, encodedInput: input))
        }
        for badInput in [Data("invalid!!".utf8), Data(Data("[]".utf8).base64EncodedString().utf8)] {
            XCTAssertThrowsError(try PipedItemOperation(arguments: ["create", "item"], encodedInput: badInput))
        }
    }

    func testRequestWireFormatPreservesInputAndOlderClients() throws {
        let original = Request(arguments: ["create", "item"], standardInput: item)
        let decoded = try JSONDecoder().decode(Request.self, from: JSONEncoder().encode(original))
        XCTAssertEqual(decoded.standardInput, item)
        let old = try JSONDecoder().decode(Request.self, from: Data(#"{"arguments":["status"]}"#.utf8))
        XCTAssertNil(old.standardInput)
    }

    func testHTTPContentLengthAndChunkedResponses() throws {
        let fixed = try response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        XCTAssertEqual(fixed.status, 200)
        XCTAssertEqual(fixed.body, Data("{}".utf8))
        let chunked = try response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
        XCTAssertEqual(chunked.body, fixed.body)
    }

    func testHTTPBoundsAndMalformedChunkAreRejected() {
        for wire in [
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n",
            "HTTP/1.1 200 OK\r\nX-Long: " + String(repeating: "x", count: 9000) + "\r\n\r\n",
        ] {
            XCTAssertThrowsError(try response(wire, maximumBytes: 4))
        }
    }

    func testErrorsDoNotExposeAuthenticationResponse() {
        let secret = "synthetic-session-must-not-escape"
        for body in [Data(secret.utf8), Data("{\"success\":false,\"data\":\"\(secret)\"}".utf8)] {
            XCTAssertThrowsError(try successfulPayloadObject(PayloadHTTPResponse(status: 400, body: body))) {
                XCTAssertFalse(String(describing: $0).contains(secret))
            }
        }
    }

    func testPrivateChildSeparatesInputsSuppressesUnlockAndIsReaped() throws {
        let result = try syntheticChild(mode: "success")
        XCTAssertEqual(result.status, 0)
        XCTAssertEqual(result.stdout, "{\"name\":\"synthetic item\"}\n")
        XCTAssertFalse(result.stdout.contains("synthetic-session"))
        XCTAssertEqual(result.stderr, "")
    }

    func testPrivateChildTimeoutAndFailureAreReaped() throws {
        XCTAssertThrowsError(try syntheticChild(mode: "timeout", timeout: 0.2)) {
            XCTAssertTrue(String(describing: $0).contains("timed out"))
        }
        XCTAssertThrowsError(try syntheticChild(mode: "failure")) {
            XCTAssertFalse(String(describing: $0).contains("synthetic-session"))
        }
    }

    func testDaemonValidatesBeforeAuthenticationAndKeepsCredentialSeparate() throws {
        let path = "/tmp/bwt-pipe-\(UUID().uuidString.prefix(12)).sock"
        let finished = expectation(description: "daemon exited")
        let input = Data(item.base64EncodedString().utf8)
        var authorized = 0
        var payloadCalls = 0
        DispatchQueue.global().async {
            defer { finished.fulfill() }
            do {
                try runDaemon(path: path, lockFilePath: path + ".lock", timeout: 3,
                              payloadRunner: { operation, credential in
                    payloadCalls += 1
                    XCTAssertEqual(operation.path, "/object/item")
                    XCTAssertEqual(credential, Data("synthetic-master".utf8))
                    return Response(status: 0, stdout: "created", stderr: "")
                }, prepare: {}, authenticator: { authorized += 1 },
                              credentialReader: { Data("synthetic-master".utf8) },
                              processRunner: { arguments, _, _ in
                    XCTAssertEqual(arguments, ["lock"])
                    return Response(status: 0, stdout: "", stderr: "")
                })
            } catch { XCTFail("Synthetic daemon failed: \(error)") }
        }
        defer { unlink(path); unlink(path + ".lock") }
        for _ in 0..<200 {
            if FileManager.default.fileExists(atPath: path) { break }
            usleep(10_000)
        }
        let invalid = try sendRequest(["login"], standardInput: input, path: path, spawn: {})
        XCTAssertNotEqual(invalid.status, 0)
        XCTAssertEqual(authorized, 0)
        let valid = try sendRequest(["create", "item"], standardInput: input, path: path, spawn: {})
        XCTAssertEqual(valid.stdout, "created")
        _ = try sendRequest(["lock"], path: path, spawn: {})
        wait(for: [finished], timeout: 4)
        XCTAssertEqual(authorized, 1)
        XCTAssertEqual(payloadCalls, 1)
    }

    private func response(_ wire: String, maximumBytes: Int = 1024) throws -> PayloadHTTPResponse {
        var descriptors = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors), 0)
        defer { descriptors.forEach { close($0) } }
        var capacity: Int32 = 65536
        XCTAssertEqual(setsockopt(descriptors[1], SOL_SOCKET, SO_SNDBUF, &capacity,
                                 socklen_t(MemoryLayout<Int32>.size)), 0)
        try writeAll(descriptors[1], data: Data(wire.utf8))
        let client = try PayloadHTTPClient(descriptor: descriptors[0], timeout: 0.2, maximumBodyBytes: maximumBytes)
        return try client.request(method: "POST", path: "/test", body: Data())
    }

    private func syntheticChild(mode: String, timeout: TimeInterval = 3) throws -> Response {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let pidPath = directory.appendingPathComponent("pid")
        defer {
            if let value = try? String(contentsOf: pidPath), let pid = Int32(value) {
                XCTAssertEqual(kill(pid, 0), -1, "Private child must be reaped")
                XCTAssertEqual(errno, ESRCH)
            } else { XCTFail("Synthetic child did not start") }
        }
        let script = #"""
import json, os, signal, socket, sys, time
with open(sys.argv[1], 'w') as f: f.write(str(os.getpid()))
signal.signal(signal.SIGTERM, signal.SIG_IGN)
assert 'BW_SESSION' not in os.environ and 'BW_TOUCH_MASTER' not in os.environ
s = socket.socket(fileno=0)
r = s.makefile('rb')
def request():
    first = r.readline().decode().strip().split()
    headers = {}
    while True:
        line = r.readline()
        if line == b'\r\n': break
        key, value = line.decode().split(':', 1)
        headers[key.lower()] = value.strip()
    return first[:2], json.loads(r.read(int(headers['content-length'])))
def respond(body):
    data = json.dumps(body).encode()
    s.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(data)).encode() + b'\r\n\r\n' + data)
first, body = request()
assert first == ['POST', '/unlock'] and body == {'password': 'synthetic-master'}
if sys.argv[2] == 'timeout': time.sleep(30)
respond({'success': sys.argv[2] != 'failure', 'data': {'raw': 'synthetic-session-must-not-escape'}})
if sys.argv[2] == 'failure': time.sleep(30)
first, body = request()
assert first == ['POST', '/object/item'] and body['name'] == 'synthetic item'
respond({'success': True, 'data': {'name': body['name']}})
time.sleep(30)
"""#
        let operation = try PipedItemOperation(arguments: ["create", "item"],
                                               encodedInput: Data(item.base64EncodedString().utf8))
        return try runPipedItemOperation(operation, credential: Data("synthetic-master".utf8),
                                        executablePath: "/usr/bin/python3",
                                        launchArguments: ["-c", script, pidPath.path, mode],
                                        inheritedEnvironment: ["BW_SESSION": "synthetic-session",
                                                               "BW_TOUCH_MASTER": "synthetic-master"],
                                        timeout: timeout)
    }
}
