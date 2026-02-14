# blerpc-protocol-swift

BLE RPC protocol library for Swift.

Part of the [bleRPC](https://blerpc.net) project.

## Overview

Swift implementation of the bleRPC binary protocol:

- Container fragmentation and reassembly with MTU-aware splitting
- Command packet encoding/decoding with protobuf payload support
- Control messages (timeout, stream end, capabilities, error)

No external dependencies — pure Swift.

## Installation

Add the package via Swift Package Manager:

```swift
dependencies: [
    .package(url: "https://github.com/tdaira/blerpc-protocol-swift", from: "0.1.0")
]
```

## Requirements

- iOS 16.0+
- macOS 13.0+
- Swift 5.9+

## License

[LGPL-3.0](LICENSE)
