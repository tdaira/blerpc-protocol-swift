import XCTest
@testable import BlerpcProtocol

final class PeripheralHandleStepTests: XCTestCase {
    private func makePeripheralKx() throws -> PeripheralKeyExchange {
        let xKp = BlerpcCrypto.X25519KeyPair()
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        return try PeripheralKeyExchange(
            x25519PrivateKey: xKp.privateKey.rawRepresentation,
            ed25519PrivateKey: edKp.privateKey.rawRepresentation
        )
    }

    func testHandleStep1() throws {
        let kx = try makePeripheralKx()
        let centralKp = BlerpcCrypto.X25519KeyPair()
        let step1 = BlerpcCrypto.buildStep1Payload(centralX25519Pubkey: centralKp.publicKeyRaw)

        let (response, session) = try kx.handleStep(step1)
        XCTAssertEqual(response[0], keyExchangeStep2)
        XCTAssertEqual(response.count, 129)
        XCTAssertNil(session)
    }

    func testHandleStep3() throws {
        let kx = try makePeripheralKx()
        let centralKx = CentralKeyExchange()

        let step1 = centralKx.start()
        let (step2, session1) = try kx.handleStep(step1)
        XCTAssertNil(session1)

        let step3 = try centralKx.processStep2(step2)
        let (step4, session2) = try kx.handleStep(step3)
        XCTAssertEqual(step4[0], keyExchangeStep4)
        XCTAssertEqual(step4.count, 45)
        XCTAssertNotNil(session2)
    }

    func testHandleStepInvalid() throws {
        let kx = try makePeripheralKx()
        let payload = Data([keyExchangeStep2]) + Data(count: 128)
        XCTAssertThrowsError(try kx.handleStep(payload))
    }

    func testHandleStepEmpty() throws {
        let kx = try makePeripheralKx()
        XCTAssertThrowsError(try kx.handleStep(Data()))
    }
}

final class CounterZeroReplayTests: XCTestCase {
    func testCounterZeroReplayAttack() throws {
        let xKp = BlerpcCrypto.X25519KeyPair()
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let periphKx = try PeripheralKeyExchange(
            x25519PrivateKey: xKp.privateKey.rawRepresentation,
            ed25519PrivateKey: edKp.privateKey.rawRepresentation
        )

        let centralKx = CentralKeyExchange()
        let step1 = centralKx.start()
        let step2 = try periphKx.processStep1(step1)
        let step3 = try centralKx.processStep2(step2)
        let (step4, periphSession) = try periphKx.processStep3(step3)
        let centralSession = try centralKx.finish(step4)

        // Encrypt a message (counter=0)
        let enc0 = try centralSession.encrypt(Data("msg0".utf8))
        // First decrypt succeeds
        let _ = try periphSession.decrypt(enc0)
        // Replay of counter-0 must fail
        XCTAssertThrowsError(try periphSession.decrypt(enc0)) { error in
            if case BlerpcCryptoError.replayDetected = error {
                // expected
            } else {
                XCTFail("Expected replayDetected error, got \(error)")
            }
        }
    }
}

final class CentralPerformKeyExchangeTests: XCTestCase {
    func testFullHandshake() async throws {
        let xKp = BlerpcCrypto.X25519KeyPair()
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let periphKx = try PeripheralKeyExchange(
            x25519PrivateKey: xKp.privateKey.rawRepresentation,
            ed25519PrivateKey: edKp.privateKey.rawRepresentation
        )

        var payloads: [Data] = []
        var periphSession: BlerpcCryptoSession?

        let session = try await BlerpcCrypto.centralPerformKeyExchange(
            send: { payload in
                let (response, sess) = try periphKx.handleStep(payload)
                if let s = sess { periphSession = s }
                payloads.append(response)
            },
            receive: {
                payloads.removeFirst()
            }
        )

        XCTAssertNotNil(periphSession)

        // Verify sessions work
        let encrypted = try session.encrypt(Data("test".utf8))
        let decrypted = try periphSession!.decrypt(encrypted)
        XCTAssertEqual(decrypted, Data("test".utf8))
    }

    func testVerifyCbReject() async throws {
        let xKp = BlerpcCrypto.X25519KeyPair()
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let periphKx = try PeripheralKeyExchange(
            x25519PrivateKey: xKp.privateKey.rawRepresentation,
            ed25519PrivateKey: edKp.privateKey.rawRepresentation
        )

        var payloads: [Data] = []

        do {
            _ = try await BlerpcCrypto.centralPerformKeyExchange(
                send: { payload in
                    let (response, _) = try periphKx.handleStep(payload)
                    payloads.append(response)
                },
                receive: {
                    payloads.removeFirst()
                },
                verifyKeyCb: { _ in false }
            )
            XCTFail("Expected error")
        } catch {
            // Expected
        }
    }

    func testVerifyCbAccept() async throws {
        let xKp = BlerpcCrypto.X25519KeyPair()
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let periphKx = try PeripheralKeyExchange(
            x25519PrivateKey: xKp.privateKey.rawRepresentation,
            ed25519PrivateKey: edKp.privateKey.rawRepresentation
        )

        var payloads: [Data] = []
        var seenKeys: [Data] = []

        let session = try await BlerpcCrypto.centralPerformKeyExchange(
            send: { payload in
                let (response, _) = try periphKx.handleStep(payload)
                payloads.append(response)
            },
            receive: {
                payloads.removeFirst()
            },
            verifyKeyCb: { key in
                seenKeys.append(key)
                return true
            }
        )

        XCTAssertNotNil(session)
        XCTAssertEqual(seenKeys.count, 1)
        XCTAssertEqual(seenKeys[0], edKp.publicKeyRaw)
    }
}
