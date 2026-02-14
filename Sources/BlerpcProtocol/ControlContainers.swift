import Foundation

public func makeTimeoutRequest(transactionId: UInt8, sequenceNumber: UInt8 = 0) -> Container {
    Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .timeout
    )
}

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

public func makeStreamEndC2P(transactionId: UInt8, sequenceNumber: UInt8 = 0) -> Container {
    Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .streamEndC2P
    )
}

public func makeStreamEndP2C(transactionId: UInt8, sequenceNumber: UInt8 = 0) -> Container {
    Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .streamEndP2C
    )
}

public func makeCapabilitiesRequest(transactionId: UInt8, sequenceNumber: UInt8 = 0) -> Container {
    Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .capabilities
    )
}

public func makeCapabilitiesResponse(
    transactionId: UInt8,
    maxRequestPayloadSize: UInt16,
    maxResponsePayloadSize: UInt16,
    sequenceNumber: UInt8 = 0
) -> Container {
    var payload = Data(count: 4)
    payload[0] = UInt8(maxRequestPayloadSize & 0xFF)
    payload[1] = UInt8(maxRequestPayloadSize >> 8)
    payload[2] = UInt8(maxResponsePayloadSize & 0xFF)
    payload[3] = UInt8(maxResponsePayloadSize >> 8)
    return Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .capabilities,
        payload: payload
    )
}

public func makeErrorResponse(transactionId: UInt8, errorCode: UInt8, sequenceNumber: UInt8 = 0) -> Container {
    Container(
        transactionId: transactionId,
        sequenceNumber: sequenceNumber,
        containerType: .control,
        controlCmd: .error,
        payload: Data([errorCode])
    )
}
