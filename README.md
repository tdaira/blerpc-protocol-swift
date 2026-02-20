# blerpc-protocol-swift

BLE RPC protocol library for Swift.

Part of the [bleRPC](https://blerpc.net) project.

## Overview

Swift implementation of the bleRPC binary protocol:

- Container fragmentation and reassembly with MTU-aware splitting
- Command packet encoding/decoding with protobuf payload support
- Control messages (timeout, stream end, capabilities, error)
- **Encryption layer** — E2E encryption with X25519 key exchange, Ed25519 signatures, and AES-128-GCM

No external dependencies — pure Swift (uses CryptoKit).

## Installation

Add the package via Swift Package Manager:

```swift
dependencies: [
    .package(url: "https://github.com/tdaira/blerpc-protocol-swift", from: "0.3.0")
]
```

## Encryption

The library provides E2E encryption using a 4-step key exchange protocol (X25519 ECDH + Ed25519 signatures) and AES-128-GCM session encryption.

```swift
import BlerpcProtocol

// Perform key exchange (central side)
let session = try await BlerpcCrypto.centralPerformKeyExchange(
    send: { data in try await bleSend(data) },
    receive: { try await bleReceive() }
)

// Encrypt outgoing commands
let ciphertext = try session.encrypt(plaintext)

// Decrypt incoming commands
let plaintext = try session.decrypt(ciphertext)
```

## Requirements

- iOS 16.0+
- macOS 13.0+
- Swift 5.9+

## License

[LGPL-3.0](LICENSE) with [Static Linking Exception](LICENSING_EXCEPTION)
