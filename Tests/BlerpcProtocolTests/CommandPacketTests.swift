import XCTest
@testable import BlerpcProtocol

final class CommandPacketTests: XCTestCase {
    func testRequestRoundtrip() throws {
        let packet = CommandPacket(
            cmdType: .request,
            cmdName: "echo",
            data: Data([0x0A, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F])
        )
        let serialized = try packet.serialize()
        let deserialized = try CommandPacket.deserialize(serialized)

        XCTAssertEqual(deserialized.cmdType, .request)
        XCTAssertEqual(deserialized.cmdName, "echo")
        XCTAssertEqual(deserialized.data, packet.data)

        // Bit 7 should be 0 for REQUEST
        XCTAssertEqual(serialized[0] >> 7, 0)
    }

    func testResponseRoundtrip() throws {
        let packet = CommandPacket(
            cmdType: .response,
            cmdName: "flash_read",
            data: Data([0xFF, 0xFE])
        )
        let serialized = try packet.serialize()
        let deserialized = try CommandPacket.deserialize(serialized)

        XCTAssertEqual(deserialized.cmdType, .response)
        XCTAssertEqual(deserialized.cmdName, "flash_read")
        XCTAssertEqual(deserialized.data, packet.data)

        // Bit 7 should be 1 for RESPONSE
        XCTAssertEqual(serialized[0] >> 7, 1)
    }

    func testEmptyData() throws {
        let packet = CommandPacket(cmdType: .request, cmdName: "test")
        let serialized = try packet.serialize()
        let deserialized = try CommandPacket.deserialize(serialized)

        XCTAssertEqual(deserialized.cmdName, "test")
        XCTAssertEqual(deserialized.data, Data())
    }

    func testDataLengthLittleEndian() throws {
        let packet = CommandPacket(
            cmdType: .request,
            cmdName: "x",
            data: Data(repeating: 0xAA, count: 300)
        )
        let serialized = try packet.serialize()

        // Data length at offset 2 + nameLen(1) = offset 3, stored as LE u16
        let dataLenLow = serialized[3]
        let dataLenHigh = serialized[4]
        let dataLen = Int(dataLenLow) | (Int(dataLenHigh) << 8)
        XCTAssertEqual(dataLen, 300)
    }

    func testDeserializeTooShort() {
        XCTAssertThrowsError(try CommandPacket.deserialize(Data([0x00]))) { error in
            if case BlerpcProtocolError.dataTooShort = error {
                // expected
            } else {
                XCTFail("Expected dataTooShort error")
            }
        }
    }

    func testEquality() throws {
        let a = CommandPacket(cmdType: .request, cmdName: "echo", data: Data([1, 2, 3]))
        let b = CommandPacket(cmdType: .request, cmdName: "echo", data: Data([1, 2, 3]))
        let c = CommandPacket(cmdType: .request, cmdName: "echo", data: Data([1, 2, 4]))
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }
}
