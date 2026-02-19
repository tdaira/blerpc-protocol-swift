import XCTest
@testable import BlerpcProtocol

final class ContainerTests: XCTestCase {
    func testFirstContainerRoundtrip() throws {
        let payload = Data([0x01, 0x02, 0x03])
        let container = Container(
            transactionId: 5,
            sequenceNumber: 0,
            containerType: .first,
            totalLength: 100,
            payload: payload
        )
        let serialized = container.serialize()
        let deserialized = try Container.deserialize(serialized)

        XCTAssertEqual(deserialized.transactionId, 5)
        XCTAssertEqual(deserialized.sequenceNumber, 0)
        XCTAssertEqual(deserialized.containerType, .first)
        XCTAssertEqual(deserialized.totalLength, 100)
        XCTAssertEqual(deserialized.payload, payload)
    }

    func testSubsequentContainerRoundtrip() throws {
        let payload = Data([0xAA, 0xBB])
        let container = Container(
            transactionId: 7,
            sequenceNumber: 3,
            containerType: .subsequent,
            payload: payload
        )
        let serialized = container.serialize()
        let deserialized = try Container.deserialize(serialized)

        XCTAssertEqual(deserialized.transactionId, 7)
        XCTAssertEqual(deserialized.sequenceNumber, 3)
        XCTAssertEqual(deserialized.containerType, .subsequent)
        XCTAssertEqual(deserialized.payload, payload)
    }

    func testControlContainerRoundtrip() throws {
        let container = Container(
            transactionId: 10,
            sequenceNumber: 0,
            containerType: .control,
            controlCmd: .timeout,
            payload: Data([0x64, 0x00])
        )
        let serialized = container.serialize()
        let deserialized = try Container.deserialize(serialized)

        XCTAssertEqual(deserialized.containerType, .control)
        XCTAssertEqual(deserialized.controlCmd, .timeout)
        XCTAssertEqual(deserialized.payload, Data([0x64, 0x00]))
    }

    func testFlagsEncoding() {
        // FIRST: type=0x00, bits 7-6 = 00
        let first = Container(transactionId: 0, sequenceNumber: 0, containerType: .first)
        let firstBytes = first.serialize()
        XCTAssertEqual(firstBytes[2] >> 6, 0x00)

        // SUBSEQUENT: type=0x01, bits 7-6 = 01
        let subsequent = Container(transactionId: 0, sequenceNumber: 0, containerType: .subsequent)
        let subsequentBytes = subsequent.serialize()
        XCTAssertEqual(subsequentBytes[2] >> 6, 0x01)

        // CONTROL: type=0x03, bits 7-6 = 11
        let control = Container(transactionId: 0, sequenceNumber: 0, containerType: .control, controlCmd: .streamEndC2P)
        let controlBytes = control.serialize()
        XCTAssertEqual(controlBytes[2] >> 6, 0x03)
        XCTAssertEqual((controlBytes[2] >> 2) & 0x0F, ControlCmd.streamEndC2P.rawValue)
    }

    func testHeaderSizes() {
        let firstContainer = Container(transactionId: 0, sequenceNumber: 0, containerType: .first)
        XCTAssertEqual(firstContainer.serialize().count, firstHeaderSize)

        let subsequentContainer = Container(transactionId: 0, sequenceNumber: 0, containerType: .subsequent)
        XCTAssertEqual(subsequentContainer.serialize().count, subsequentHeaderSize)

        let controlContainer = Container(
            transactionId: 0, sequenceNumber: 0,
            containerType: .control, controlCmd: .timeout
        )
        XCTAssertEqual(controlContainer.serialize().count, controlHeaderSize)
    }

    func testDeserializeTooShort() {
        XCTAssertThrowsError(try Container.deserialize(Data([0x00]))) { error in
            if case BlerpcProtocolError.dataTooShort(let n) = error {
                XCTAssertEqual(n, 1)
            } else {
                XCTFail("Expected dataTooShort error")
            }
        }
    }

    func testFirstContainerPayloadLengthExceedsData() {
        // FIRST container header (6 bytes): tid=0, seq=0, flags=0x00 (type=FIRST),
        // totalLength=100 (LE), payloadLength=10 (claims 10 bytes but only 2 available)
        let data = Data([0x00, 0x00, 0x00, 0x64, 0x00, 0x0A, 0xAA, 0xBB])
        XCTAssertThrowsError(try Container.deserialize(data)) { error in
            if case BlerpcProtocolError.dataTooShort = error {
                // expected
            } else {
                XCTFail("Expected dataTooShort error, got \(error)")
            }
        }
    }

    func testSubsequentContainerPayloadLengthExceedsData() {
        // SUBSEQUENT container header (4 bytes): tid=0, seq=0, flags=0x40 (type=SUBSEQUENT),
        // payloadLength=10 (claims 10 bytes but only 1 available)
        let data = Data([0x00, 0x00, 0x40, 0x0A, 0xCC])
        XCTAssertThrowsError(try Container.deserialize(data)) { error in
            if case BlerpcProtocolError.dataTooShort = error {
                // expected
            } else {
                XCTFail("Expected dataTooShort error, got \(error)")
            }
        }
    }

    func testEquality() {
        let payload1 = Data([1, 2, 3])
        let payload2 = Data([1, 2, 4])
        let a = Container(
            transactionId: 1, sequenceNumber: 0,
            containerType: .first, totalLength: 3, payload: payload1
        )
        let b = Container(
            transactionId: 1, sequenceNumber: 0,
            containerType: .first, totalLength: 3, payload: payload1
        )
        let c = Container(
            transactionId: 1, sequenceNumber: 0,
            containerType: .first, totalLength: 3, payload: payload2
        )
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }
}
