import CryptoKit
import Foundation

/// Direction bytes for nonce construction.
public let directionC2P: UInt8 = 0x00
public let directionP2C: UInt8 = 0x01

/// Confirmation plaintexts.
public let confirmCentral = Data("BLERPC_CONFIRM_C".utf8)
public let confirmPeripheral = Data("BLERPC_CONFIRM_P".utf8)

/// Key exchange step constants.
public let keyExchangeStep1: UInt8 = 0x01
public let keyExchangeStep2: UInt8 = 0x02
public let keyExchangeStep3: UInt8 = 0x03
public let keyExchangeStep4: UInt8 = 0x04

/// Errors thrown by bleRPC cryptographic operations.
public enum BlerpcCryptoError: Error {
    case invalidPayload(String)
    case signatureVerificationFailed
    case decryptionFailed
    case replayDetected
    case sessionNotActive
    case keyExchangeFailed(String)
}

/// Cryptographic operations for bleRPC E2E encryption.
///
/// Provides X25519 key agreement, Ed25519 signing/verification,
/// AES-128-GCM encryption, and HKDF-SHA256 key derivation.
public struct BlerpcCrypto {
    /// An X25519 key pair for ECDH key agreement.
    public struct X25519KeyPair {
        public let privateKey: Curve25519.KeyAgreement.PrivateKey
        public let publicKeyRaw: Data

        public init() {
            let privKey = Curve25519.KeyAgreement.PrivateKey()
            self.privateKey = privKey
            self.publicKeyRaw = Data(privKey.publicKey.rawRepresentation)
        }

        public init(privateKeyRaw: Data) throws {
            self.privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyRaw)
            self.publicKeyRaw = Data(self.privateKey.publicKey.rawRepresentation)
        }
    }

    /// An Ed25519 key pair for digital signatures.
    public struct Ed25519KeyPair {
        public let privateKey: Curve25519.Signing.PrivateKey
        public let publicKeyRaw: Data

        public init() {
            let privKey = Curve25519.Signing.PrivateKey()
            self.privateKey = privKey
            self.publicKeyRaw = Data(privKey.publicKey.rawRepresentation)
        }

        public init(privateKeyRaw: Data) throws {
            self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyRaw)
            self.publicKeyRaw = Data(self.privateKey.publicKey.rawRepresentation)
        }
    }

    /// Compute X25519 shared secret (32 bytes).
    public static func x25519SharedSecret(
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        peerPublicRaw: Data
    ) throws -> Data {
        let peerPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicRaw)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: peerPub)
        return shared.withUnsafeBytes { Data($0) }
    }

    /// Derive 16-byte AES-128 session key using HKDF-SHA256.
    ///
    /// Salt is `centralPubkey || peripheralPubkey`, info is `"blerpc-session-key"`.
    public static func deriveSessionKey(
        sharedSecret: Data,
        centralPubkey: Data,
        peripheralPubkey: Data
    ) -> Data {
        let salt = centralPubkey + peripheralPubkey
        let sharedSecretKey = SymmetricKey(data: sharedSecret)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: sharedSecretKey,
            salt: salt,
            info: Data("blerpc-session-key".utf8),
            outputByteCount: 16
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    /// Sign a message with Ed25519, returning a 64-byte signature.
    public static func ed25519Sign(
        privateKey: Curve25519.Signing.PrivateKey,
        message: Data
    ) throws -> Data {
        return try Data(privateKey.signature(for: message))
    }

    /// Verify an Ed25519 signature. Returns true if valid.
    public static func ed25519Verify(
        publicKeyRaw: Data,
        message: Data,
        signature: Data
    ) -> Bool {
        guard let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyRaw) else {
            return false
        }
        return pubKey.isValidSignature(signature, for: message)
    }

    private static func buildNonce(counter: UInt32, direction: UInt8) -> Data {
        var nonce = Data(count: 12)
        nonce[0] = UInt8(counter & 0xFF)
        nonce[1] = UInt8((counter >> 8) & 0xFF)
        nonce[2] = UInt8((counter >> 16) & 0xFF)
        nonce[3] = UInt8((counter >> 24) & 0xFF)
        nonce[4] = direction
        return nonce
    }

    /// Encrypt a command payload with AES-128-GCM.
    ///
    /// Output format: `[counter:4B LE][ciphertext:NB][tag:16B]`.
    public static func encryptCommand(
        sessionKey: Data,
        counter: UInt32,
        direction: UInt8,
        plaintext: Data
    ) throws -> Data {
        let nonceData = buildNonce(counter: counter, direction: direction)
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let key = SymmetricKey(data: sessionKey)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)

        var out = Data(count: 4)
        out[0] = UInt8(counter & 0xFF)
        out[1] = UInt8((counter >> 8) & 0xFF)
        out[2] = UInt8((counter >> 16) & 0xFF)
        out[3] = UInt8((counter >> 24) & 0xFF)
        out.append(sealed.ciphertext)
        out.append(sealed.tag)
        return out
    }

    /// Result of decrypting a command payload.
    public struct DecryptedCommand {
        public let counter: UInt32
        public let plaintext: Data
    }

    /// Decrypt a command payload with AES-128-GCM.
    public static func decryptCommand(
        sessionKey: Data,
        direction: UInt8,
        data: Data
    ) throws -> DecryptedCommand {
        guard data.count >= 20 else {
            throw BlerpcCryptoError.invalidPayload("Encrypted payload too short: \(data.count)")
        }

        let counter = UInt32(data[0]) | (UInt32(data[1]) << 8) |
            (UInt32(data[2]) << 16) | (UInt32(data[3]) << 24)
        let ctAndTag = data.dropFirst(4)

        let nonceData = buildNonce(counter: counter, direction: direction)
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let key = SymmetricKey(data: sessionKey)

        let tagStart = ctAndTag.count - 16
        let ciphertext = ctAndTag.prefix(tagStart)
        let tag = ctAndTag.suffix(16)

        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let plaintext = try AES.GCM.open(sealedBox, using: key)
        return DecryptedCommand(counter: counter, plaintext: Data(plaintext))
    }

    /// Encrypt a confirmation message for key exchange step 3/4.
    public static func encryptConfirmation(sessionKey: Data, message: Data) throws -> Data {
        let nonce = AES.GCM.Nonce()
        let key = SymmetricKey(data: sessionKey)
        let sealed = try AES.GCM.seal(message, using: key, nonce: nonce)

        var out = Data(nonce.withUnsafeBytes { Data($0) })
        out.append(sealed.ciphertext)
        out.append(sealed.tag)
        return out
    }

    /// Decrypt a confirmation message from key exchange step 3/4.
    public static func decryptConfirmation(sessionKey: Data, data: Data) throws -> Data {
        guard data.count >= 44 else {
            throw BlerpcCryptoError.invalidPayload("Confirmation too short: \(data.count)")
        }

        let nonceData = data.prefix(12)
        let ctAndTag = data.dropFirst(12)
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let key = SymmetricKey(data: sessionKey)

        let tagStart = ctAndTag.count - 16
        let ciphertext = ctAndTag.prefix(tagStart)
        let tag = ctAndTag.suffix(16)

        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return Data(try AES.GCM.open(sealedBox, using: key))
    }

    // MARK: - Step payload builders/parsers

    public static func buildStep1Payload(centralX25519Pubkey: Data) -> Data {
        Data([keyExchangeStep1]) + centralX25519Pubkey
    }

    public static func parseStep1Payload(_ data: Data) throws -> Data {
        guard data.count >= 33, data[0] == keyExchangeStep1 else {
            throw BlerpcCryptoError.invalidPayload("Invalid step 1 payload")
        }
        return data[1..<33]
    }

    public static func buildStep2Payload(
        peripheralX25519Pubkey: Data,
        ed25519Signature: Data,
        peripheralEd25519Pubkey: Data
    ) -> Data {
        Data([keyExchangeStep2]) + peripheralX25519Pubkey + ed25519Signature + peripheralEd25519Pubkey
    }

    public static func parseStep2Payload(_ data: Data) throws -> (Data, Data, Data) {
        guard data.count >= 129, data[0] == keyExchangeStep2 else {
            throw BlerpcCryptoError.invalidPayload("Invalid step 2 payload")
        }
        return (data[1..<33], data[33..<97], data[97..<129])
    }

    public static func buildStep3Payload(confirmationEncrypted: Data) -> Data {
        Data([keyExchangeStep3]) + confirmationEncrypted
    }

    public static func parseStep3Payload(_ data: Data) throws -> Data {
        guard data.count >= 45, data[0] == keyExchangeStep3 else {
            throw BlerpcCryptoError.invalidPayload("Invalid step 3 payload")
        }
        return data[1..<45]
    }

    public static func buildStep4Payload(confirmationEncrypted: Data) -> Data {
        Data([keyExchangeStep4]) + confirmationEncrypted
    }

    public static func parseStep4Payload(_ data: Data) throws -> Data {
        guard data.count >= 45, data[0] == keyExchangeStep4 else {
            throw BlerpcCryptoError.invalidPayload("Invalid step 4 payload")
        }
        return data[1..<45]
    }
}

/// Stateful encryption/decryption session established after key exchange.
///
/// Tracks send/receive counters and provides replay protection.
public class BlerpcCryptoSession {
    private let sessionKey: Data
    private var txCounter: UInt32 = 0
    private var rxCounter: UInt32 = 0
    private var rxFirstDone = false
    private let txDirection: UInt8
    private let rxDirection: UInt8

    public init(sessionKey: Data, isCentral: Bool) {
        self.sessionKey = sessionKey
        self.txDirection = isCentral ? directionC2P : directionP2C
        self.rxDirection = isCentral ? directionP2C : directionC2P
    }

    /// Encrypt plaintext and advance the send counter.
    public func encrypt(_ plaintext: Data) throws -> Data {
        let result = try BlerpcCrypto.encryptCommand(
            sessionKey: sessionKey, counter: txCounter, direction: txDirection, plaintext: plaintext
        )
        txCounter += 1
        return result
    }

    /// Decrypt data with replay protection. Throws on replay or auth failure.
    public func decrypt(_ data: Data) throws -> Data {
        let decrypted = try BlerpcCrypto.decryptCommand(
            sessionKey: sessionKey, direction: rxDirection, data: data
        )
        if rxFirstDone {
            guard decrypted.counter > rxCounter else {
                throw BlerpcCryptoError.replayDetected
            }
        }
        rxCounter = decrypted.counter
        rxFirstDone = true
        return decrypted.plaintext
    }
}

/// Central-side key exchange state machine.
///
/// Usage: ``start()`` → send step 1 → receive step 2 → ``processStep2(_:verifyKeyCb:)`` →
/// send step 3 → receive step 4 → ``finish(_:)`` → ``BlerpcCryptoSession``.
public class CentralKeyExchange {
    private var keyPair: BlerpcCrypto.X25519KeyPair?
    private var sessionKey: Data?

    public init() {
        keyPair = nil
        sessionKey = nil
    }

    /// Generate an ephemeral X25519 key pair and return the step 1 payload.
    public func start() -> Data {
        let kp = BlerpcCrypto.X25519KeyPair()
        keyPair = kp
        return BlerpcCrypto.buildStep1Payload(centralX25519Pubkey: kp.publicKeyRaw)
    }

    /// Process step 2 from peripheral: verify signature, derive session key,
    /// and produce step 3 payload with encrypted confirmation.
    ///
    /// - Parameter verifyKeyCb: Optional callback to verify the peripheral's Ed25519 public key (TOFU).
    public func processStep2(
        _ step2Payload: Data,
        verifyKeyCb: ((Data) -> Bool)? = nil
    ) throws -> Data {
        guard let kp = keyPair else {
            throw BlerpcCryptoError.sessionNotActive
        }

        let (periphX25519Pub, signature, periphEd25519Pub) =
            try BlerpcCrypto.parseStep2Payload(step2Payload)

        let signMessage = kp.publicKeyRaw + periphX25519Pub
        guard BlerpcCrypto.ed25519Verify(
            publicKeyRaw: periphEd25519Pub,
            message: signMessage,
            signature: signature
        ) else {
            throw BlerpcCryptoError.signatureVerificationFailed
        }

        if let cb = verifyKeyCb, !cb(periphEd25519Pub) {
            throw BlerpcCryptoError.keyExchangeFailed("Peripheral key rejected by verify callback")
        }

        let sharedSecret = try BlerpcCrypto.x25519SharedSecret(
            privateKey: kp.privateKey,
            peerPublicRaw: periphX25519Pub
        )
        sessionKey = BlerpcCrypto.deriveSessionKey(
            sharedSecret: sharedSecret,
            centralPubkey: kp.publicKeyRaw,
            peripheralPubkey: periphX25519Pub
        )

        let encryptedConfirm = try BlerpcCrypto.encryptConfirmation(
            sessionKey: sessionKey!,
            message: confirmCentral
        )
        return BlerpcCrypto.buildStep3Payload(confirmationEncrypted: encryptedConfirm)
    }

    /// Process step 4 from peripheral, verify confirmation, and return the session.
    public func finish(_ step4Payload: Data) throws -> BlerpcCryptoSession {
        guard let sk = sessionKey else {
            throw BlerpcCryptoError.sessionNotActive
        }

        let encryptedPeriph = try BlerpcCrypto.parseStep4Payload(step4Payload)
        let plaintext = try BlerpcCrypto.decryptConfirmation(sessionKey: sk, data: encryptedPeriph)
        guard plaintext == confirmPeripheral else {
            throw BlerpcCryptoError.keyExchangeFailed("Peripheral confirmation mismatch")
        }

        return BlerpcCryptoSession(sessionKey: sk, isCentral: true)
    }
}

/// Peripheral-side key exchange state machine.
///
/// Use ``handleStep(_:)`` for automatic step dispatching, or call
/// ``processStep1(_:)`` and ``processStep3(_:)`` directly.
public class PeripheralKeyExchange {
    private let x25519KeyPair: BlerpcCrypto.X25519KeyPair
    private let ed25519KeyPair: BlerpcCrypto.Ed25519KeyPair
    private var sessionKey: Data?

    public init(x25519PrivateKey: Data, ed25519PrivateKey: Data) throws {
        x25519KeyPair = try BlerpcCrypto.X25519KeyPair(privateKeyRaw: x25519PrivateKey)
        ed25519KeyPair = try BlerpcCrypto.Ed25519KeyPair(privateKeyRaw: ed25519PrivateKey)
        sessionKey = nil
    }

    /// Process step 1 from central: sign, derive session key, and produce step 2 payload.
    public func processStep1(_ step1Payload: Data) throws -> Data {
        let centralX25519Pubkey = try BlerpcCrypto.parseStep1Payload(step1Payload)

        let signMsg = centralX25519Pubkey + x25519KeyPair.publicKeyRaw
        let signature = try BlerpcCrypto.ed25519Sign(
            privateKey: ed25519KeyPair.privateKey,
            message: signMsg
        )

        let sharedSecret = try BlerpcCrypto.x25519SharedSecret(
            privateKey: x25519KeyPair.privateKey,
            peerPublicRaw: centralX25519Pubkey
        )
        sessionKey = BlerpcCrypto.deriveSessionKey(
            sharedSecret: sharedSecret,
            centralPubkey: centralX25519Pubkey,
            peripheralPubkey: x25519KeyPair.publicKeyRaw
        )

        return BlerpcCrypto.buildStep2Payload(
            peripheralX25519Pubkey: x25519KeyPair.publicKeyRaw,
            ed25519Signature: signature,
            peripheralEd25519Pubkey: ed25519KeyPair.publicKeyRaw
        )
    }

    /// Process step 3 from central: verify confirmation, produce step 4 + session.
    public func processStep3(_ step3Payload: Data) throws -> (Data, BlerpcCryptoSession) {
        guard let sk = sessionKey else {
            throw BlerpcCryptoError.sessionNotActive
        }

        let encrypted = try BlerpcCrypto.parseStep3Payload(step3Payload)
        let plaintext = try BlerpcCrypto.decryptConfirmation(sessionKey: sk, data: encrypted)
        guard plaintext == confirmCentral else {
            throw BlerpcCryptoError.keyExchangeFailed("Central confirmation mismatch")
        }

        let encryptedConfirm = try BlerpcCrypto.encryptConfirmation(
            sessionKey: sk,
            message: confirmPeripheral
        )
        let step4 = BlerpcCrypto.buildStep4Payload(confirmationEncrypted: encryptedConfirm)
        let session = BlerpcCryptoSession(sessionKey: sk, isCentral: false)

        return (step4, session)
    }

    /// Handle a single key exchange step, dispatching to ``processStep1(_:)`` or ``processStep3(_:)``.
    ///
    /// - Returns: Tuple of (response payload, session or nil if not yet established).
    public func handleStep(_ payload: Data) throws -> (Data, BlerpcCryptoSession?) {
        guard !payload.isEmpty else {
            throw BlerpcCryptoError.invalidPayload("Empty key exchange payload")
        }

        switch payload[payload.startIndex] {
        case keyExchangeStep1:
            let response = try processStep1(payload)
            return (response, nil)
        case keyExchangeStep3:
            let (step4, session) = try processStep3(payload)
            return (step4, session)
        default:
            throw BlerpcCryptoError.invalidPayload(
                "Invalid key exchange step: 0x\(String(payload[payload.startIndex], radix: 16, uppercase: false))"
            )
        }
    }
}

public extension BlerpcCrypto {
    /// Perform the complete 4-step central key exchange using send/receive callbacks.
    ///
    /// - Parameters:
    ///   - send: Callback to send a key exchange payload over BLE.
    ///   - receive: Callback to receive a key exchange payload from BLE.
    ///   - verifyKeyCb: Optional callback to verify the peripheral's Ed25519 public key.
    /// - Returns: An established ``BlerpcCryptoSession`` ready for encryption/decryption.
    static func centralPerformKeyExchange(
        send: (Data) async throws -> Void,
        receive: () async throws -> Data,
        verifyKeyCb: ((Data) -> Bool)? = nil
    ) async throws -> BlerpcCryptoSession {
        let kx = CentralKeyExchange()

        // Step 1: Send central's ephemeral public key
        let step1 = kx.start()
        try await send(step1)

        // Step 2: Receive peripheral's response
        let step2 = try await receive()

        // Step 2 -> Step 3: Verify and produce confirmation
        let step3 = try kx.processStep2(step2, verifyKeyCb: verifyKeyCb)
        try await send(step3)

        // Step 4: Receive peripheral's confirmation
        let step4 = try await receive()

        return try kx.finish(step4)
    }
}
