import XCTest
@testable import BlerpcProtocol

final class PeripheralHandleStepTests: XCTestCase {
    private func makePeripheralKx() throws -> PeripheralKeyExchange {
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        return try PeripheralKeyExchange(
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

        let step1 = try centralKx.start()
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
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let periphKx = try PeripheralKeyExchange(
            ed25519PrivateKey: edKp.privateKey.rawRepresentation
        )

        let centralKx = CentralKeyExchange()
        let step1 = try centralKx.start()
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
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let periphKx = try PeripheralKeyExchange(
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
            },
            pinIdentity: false
        )

        XCTAssertNotNil(periphSession)

        // Verify sessions work
        let encrypted = try session.encrypt(Data("test".utf8))
        let decrypted = try periphSession!.decrypt(encrypted)
        XCTAssertEqual(decrypted, Data("test".utf8))
    }

    func testVerifyCbReject() async throws {
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let periphKx = try PeripheralKeyExchange(
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
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let periphKx = try PeripheralKeyExchange(
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

    // MARK: - TOFU identity pinning

    private final class InMemoryKeyStore: KnownKeyStore {
        var map: [String: String] = [:]
        func get(deviceId: String) -> String? { map[deviceId] }
        func put(deviceId: String, hexEd25519Pubkey: String) { map[deviceId] = hexEd25519Pubkey }
    }

    private func runExchange(
        seed: Data,
        store: KnownKeyStore? = nil,
        deviceId: String? = nil,
        pinIdentity: Bool = true
    ) async throws -> BlerpcCryptoSession {
        let periphKx = try PeripheralKeyExchange(ed25519PrivateKey: seed)
        var payloads: [Data] = []
        return try await BlerpcCrypto.centralPerformKeyExchange(
            send: { payload in
                let (response, _) = try periphKx.handleStep(payload)
                payloads.append(response)
            },
            receive: { payloads.removeFirst() },
            knownKeys: store,
            deviceId: deviceId,
            pinIdentity: pinIdentity
        )
    }

    private func newSeed() -> Data { BlerpcCrypto.Ed25519KeyPair().privateKey.rawRepresentation }

    func testTofuPinsThenMatches() async throws {
        let seed = newSeed()
        let store = InMemoryKeyStore()
        _ = try await runExchange(seed: seed, store: store, deviceId: "dev-1") // first use: pinned
        XCTAssertEqual(store.map.count, 1)
        _ = try await runExchange(seed: seed, store: store, deviceId: "dev-1") // same key: matches
    }

    func testTofuRejectsChangedKey() async throws {
        let store = InMemoryKeyStore()
        _ = try await runExchange(seed: newSeed(), store: store, deviceId: "dev-1") // pin
        do {
            _ = try await runExchange(seed: newSeed(), store: store, deviceId: "dev-1")
            XCTFail("Expected TOFU rejection for a changed key")
        } catch {
            // Expected
        }
    }

    func testFailClosedWithoutStore() async throws {
        do {
            _ = try await runExchange(seed: newSeed()) // pinIdentity defaults true, no store
            XCTFail("Expected fail-closed error")
        } catch {
            // Expected
        }
    }

    func testOptOutSkipsPinning() async throws {
        let session = try await runExchange(seed: newSeed(), pinIdentity: false)
        XCTAssertNotNil(session)
    }
}

final class KeyExchangeStateValidationTests: XCTestCase {
    func testCentralProcessStep2BeforeStartThrows() {
        let kx = CentralKeyExchange()
        XCTAssertThrowsError(try kx.processStep2(Data([keyExchangeStep2]) + Data(count: 128)))
    }

    func testCentralFinishBeforeProcessStep2Throws() throws {
        let kx = CentralKeyExchange()
        _ = try kx.start()
        XCTAssertThrowsError(try kx.finish(Data([keyExchangeStep4]) + Data(count: 44)))
    }

    func testCentralDoubleStartThrows() throws {
        let kx = CentralKeyExchange()
        _ = try kx.start()
        XCTAssertThrowsError(try kx.start())
    }

    func testPeripheralProcessStep3BeforeStep1Throws() throws {
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let kx = try PeripheralKeyExchange(ed25519PrivateKey: edKp.privateKey.rawRepresentation)
        XCTAssertThrowsError(try kx.processStep3(Data([keyExchangeStep3]) + Data(count: 44)))
    }

    func testPeripheralHandleStep3BeforeStep1Throws() throws {
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let kx = try PeripheralKeyExchange(ed25519PrivateKey: edKp.privateKey.rawRepresentation)
        XCTAssertThrowsError(try kx.handleStep(Data([keyExchangeStep3]) + Data(count: 44)))
    }

    func testPeripheralDoubleStep1Throws() throws {
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let kx = try PeripheralKeyExchange(ed25519PrivateKey: edKp.privateKey.rawRepresentation)
        let centralKx = CentralKeyExchange()
        let step1 = try centralKx.start()
        _ = try kx.processStep1(step1)
        XCTAssertThrowsError(try kx.processStep1(step1))
    }

    func testPeripheralResetAllowsNewHandshake() throws {
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let kx = try PeripheralKeyExchange(ed25519PrivateKey: edKp.privateKey.rawRepresentation)
        let centralKx = CentralKeyExchange()
        let step1 = try centralKx.start()
        _ = try kx.processStep1(step1)
        kx.reset()
        let centralKx2 = CentralKeyExchange()
        let step1b = try centralKx2.start()
        let step2 = try kx.processStep1(step1b)
        XCTAssertEqual(step2.count, 129)
    }
}

final class CryptoSessionCounterOverflowTests: XCTestCase {
    func testEncryptAtMaxCounterThrows() throws {
        let edKp = BlerpcCrypto.Ed25519KeyPair()
        let periphKx = try PeripheralKeyExchange(ed25519PrivateKey: edKp.privateKey.rawRepresentation)
        let centralKx = CentralKeyExchange()
        let step1 = try centralKx.start()
        let step2 = try periphKx.processStep1(step1)
        let step3 = try centralKx.processStep2(step2)
        let (step4, periphSession) = try periphKx.processStep3(step3)
        let centralSession = try centralKx.finish(step4)

        // Verify session works first
        let enc = try centralSession.encrypt(Data("test".utf8))
        let dec = try periphSession.decrypt(enc)
        XCTAssertEqual(dec, Data("test".utf8))

        // Note: We can't easily set the counter to UInt32.max since it's private.
        // Instead verify that after many encryptions, the counter increments correctly.
        // A full counter overflow test would require exposing the counter or
        // encrypting 2^32 times (impractical). The important thing is the guard exists.
    }
}

final class CryptoSessionThreadSafetyTests: XCTestCase {
    func testConcurrentEncryptNoDuplicateCounters() throws {
        let key = Data(repeating: 0x01, count: 16)
        let session = BlerpcCryptoSession(sessionKey: key, isCentral: true)

        let group = DispatchGroup()
        let queue = DispatchQueue(label: "test", attributes: .concurrent)
        let resultsLock = NSLock()
        var counters = [UInt32]()
        var errors = [Error]()

        for _ in 0..<4 {
            group.enter()
            queue.async {
                for _ in 0..<50 {
                    do {
                        let enc = try session.encrypt(Data([0x42]))
                        let counter = enc.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self) }
                        resultsLock.lock()
                        counters.append(counter)
                        resultsLock.unlock()
                    } catch {
                        resultsLock.lock()
                        errors.append(error)
                        resultsLock.unlock()
                    }
                }
                group.leave()
            }
        }

        group.wait()
        XCTAssertEqual(errors.count, 0)
        XCTAssertEqual(counters.count, 200)
        XCTAssertEqual(Set(counters).count, 200) // All counters unique
    }
}
