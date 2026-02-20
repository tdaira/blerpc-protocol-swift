import Foundation

/// Create a timeout request control container.
public func makeTimeoutRequest(transactionId: UInt8, sequenceNumber: UInt8 = 0) -> Container {
    Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .timeout
    )
}

/// Create a timeout response control container with the given timeout in milliseconds.
public func makeTimeoutResponse(transactionId: UInt8, timeoutMs: UInt16, sequenceNumber: UInt8 = 0) -> Container {
    var payload = Data(count: 2)
    payload[0] = UInt8(timeoutMs & 0xFF)
    payload[1] = UInt8(timeoutMs >> 8)
    return Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .timeout,
        payload: payload
    )
}

/// Create a stream-end control container (central to peripheral direction).
public func makeStreamEndC2P(transactionId: UInt8, sequenceNumber: UInt8 = 0) -> Container {
    Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .streamEndC2P
    )
}

/// Create a stream-end control container (peripheral to central direction).
public func makeStreamEndP2C(transactionId: UInt8, sequenceNumber: UInt8 = 0) -> Container {
    Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .streamEndP2C
    )
}

/// Create a capabilities request control container.
public func makeCapabilitiesRequest(
    transactionId: UInt8,
    maxRequestPayloadSize: UInt16 = 0,
    maxResponsePayloadSize: UInt16 = 0,
    flags: UInt16 = 0,
    sequenceNumber: UInt8 = 0
) -> Container {
    var payload = Data(count: 6)
    payload[0] = UInt8(maxRequestPayloadSize & 0xFF)
    payload[1] = UInt8(maxRequestPayloadSize >> 8)
    payload[2] = UInt8(maxResponsePayloadSize & 0xFF)
    payload[3] = UInt8(maxResponsePayloadSize >> 8)
    payload[4] = UInt8(flags & 0xFF)
    payload[5] = UInt8(flags >> 8)
    return Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .capabilities,
        payload: payload
    )
}

/// Create a capabilities response control container.
public func makeCapabilitiesResponse(
    transactionId: UInt8,
    maxRequestPayloadSize: UInt16,
    maxResponsePayloadSize: UInt16,
    flags: UInt16 = 0,
    sequenceNumber: UInt8 = 0
) -> Container {
    var payload = Data(count: 6)
    payload[0] = UInt8(maxRequestPayloadSize & 0xFF)
    payload[1] = UInt8(maxRequestPayloadSize >> 8)
    payload[2] = UInt8(maxResponsePayloadSize & 0xFF)
    payload[3] = UInt8(maxResponsePayloadSize >> 8)
    payload[4] = UInt8(flags & 0xFF)
    payload[5] = UInt8(flags >> 8)
    return Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .capabilities,
        payload: payload
    )
}

/// Create an error response control container with the given error code.
public func makeErrorResponse(transactionId: UInt8, errorCode: UInt8, sequenceNumber: UInt8 = 0) -> Container {
    Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .error,
        payload: Data([errorCode])
    )
}

/// Create a key exchange control container with the given payload.
public func makeKeyExchange(transactionId: UInt8, payload: Data, sequenceNumber: UInt8 = 0) -> Container {
    Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .keyExchange,
        payload: payload
    )
}
