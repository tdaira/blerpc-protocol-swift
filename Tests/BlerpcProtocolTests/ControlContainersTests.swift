import XCTest
@testable import BlerpcProtocol

final class ControlContainersTests: XCTestCase {
    func testTimeoutRoundtrip() throws {
        let req = makeTimeoutRequest(transactionId: 1)
        XCTAssertEqual(req.containerType, .control)
        XCTAssertEqual(req.controlCmd, .timeout)
        XCTAssertEqual(req.payload.count, 0)

        let resp = makeTimeoutResponse(transactionId: 1, timeoutMs: 500)
        let serialized = resp.serialize()
        let deserialized = try Container.deserialize(serialized)
        XCTAssertEqual(deserialized.containerType, .control)
        XCTAssertEqual(deserialized.controlCmd, .timeout)
        XCTAssertEqual(deserialized.payload.count, 2)

        let ms = UInt16(deserialized.payload[0]) | (UInt16(deserialized.payload[1]) << 8)
        XCTAssertEqual(ms, 500)
    }

    func testStreamEndC2P() throws {
        let container = makeStreamEndC2P(transactionId: 5)
        let serialized = container.serialize()
        let deserialized = try Container.deserialize(serialized)

        XCTAssertEqual(deserialized.containerType, .control)
        XCTAssertEqual(deserialized.controlCmd, .streamEndC2P)
        XCTAssertEqual(deserialized.payload.count, 0)
    }

    func testStreamEndP2C() throws {
        let container = makeStreamEndP2C(transactionId: 6)
        let serialized = container.serialize()
        let deserialized = try Container.deserialize(serialized)

        XCTAssertEqual(deserialized.containerType, .control)
        XCTAssertEqual(deserialized.controlCmd, .streamEndP2C)
    }

    func testCapabilitiesRoundtrip() throws {
        let req = makeCapabilitiesRequest(transactionId: 2)
        XCTAssertEqual(req.containerType, .control)
        XCTAssertEqual(req.controlCmd, .capabilities)
        XCTAssertEqual(req.payload.count, 6)

        let resp = makeCapabilitiesResponse(
            transactionId: 2,
            maxRequestPayloadSize: 256,
            maxResponsePayloadSize: 4096,
            flags: 0x0001
        )
        let serialized = resp.serialize()
        let deserialized = try Container.deserialize(serialized)
        XCTAssertEqual(deserialized.payload.count, 6)

        let reqSize = UInt16(deserialized.payload[0]) | (UInt16(deserialized.payload[1]) << 8)
        let respSize = UInt16(deserialized.payload[2]) | (UInt16(deserialized.payload[3]) << 8)
        let flags = UInt16(deserialized.payload[4]) | (UInt16(deserialized.payload[5]) << 8)
        XCTAssertEqual(reqSize, 256)
        XCTAssertEqual(respSize, 4096)
        XCTAssertEqual(flags, 0x0001)
    }

    func testErrorResponse() throws {
        let container = makeErrorResponse(transactionId: 3, errorCode: blerpcErrorResponseTooLarge)
        let serialized = container.serialize()
        let deserialized = try Container.deserialize(serialized)

        XCTAssertEqual(deserialized.containerType, .control)
        XCTAssertEqual(deserialized.controlCmd, .error)
        XCTAssertEqual(deserialized.payload.count, 1)
        XCTAssertEqual(deserialized.payload[0], blerpcErrorResponseTooLarge)
    }
}
