import XCTest
@testable import BlerpcProtocol

final class ContainerSplitterTests: XCTestCase {
    func testSmallPayloadSingleContainer() throws {
        let splitter = ContainerSplitter(mtu: 247)
        let payload = Data([0x01, 0x02, 0x03])
        let containers = try splitter.split(payload, transactionId: 0)

        XCTAssertEqual(containers.count, 1)
        XCTAssertEqual(containers[0].containerType, .first)
        XCTAssertEqual(containers[0].sequenceNumber, 0)
        XCTAssertEqual(containers[0].totalLength, 3)
        XCTAssertEqual(containers[0].payload, payload)
    }

    func testEmptyPayload() throws {
        let splitter = ContainerSplitter(mtu: 247)
        let containers = try splitter.split(Data(), transactionId: 0)

        XCTAssertEqual(containers.count, 1)
        XCTAssertEqual(containers[0].containerType, .first)
        XCTAssertEqual(containers[0].totalLength, 0)
        XCTAssertEqual(containers[0].payload, Data())
    }

    func testLargePayloadMultipleContainers() throws {
        let splitter = ContainerSplitter(mtu: 27) // effectiveMtu = 24
        let payload = Data(repeating: 0xAA, count: 512)
        let containers = try splitter.split(payload, transactionId: 42)

        XCTAssertGreaterThan(containers.count, 1)
        XCTAssertEqual(containers[0].containerType, .first)
        XCTAssertEqual(containers[0].transactionId, 42)
        XCTAssertEqual(containers[0].sequenceNumber, 0)
        XCTAssertEqual(Int(containers[0].totalLength), 512)

        // All subsequent containers should have correct type and sequence
        for i in 1..<containers.count {
            XCTAssertEqual(containers[i].containerType, .subsequent)
            XCTAssertEqual(containers[i].sequenceNumber, UInt8(i))
            XCTAssertEqual(containers[i].transactionId, 42)
        }

        // Reassemble and verify
        var reassembled = Data()
        for c in containers {
            reassembled.append(c.payload)
        }
        XCTAssertEqual(reassembled, payload)
    }

    func testExactFitFirstContainer() throws {
        let splitter = ContainerSplitter(mtu: 247) // effectiveMtu=244, firstMax=238
        let payload = Data(repeating: 0xBB, count: 238)
        let containers = try splitter.split(payload, transactionId: 0)

        XCTAssertEqual(containers.count, 1)
        XCTAssertEqual(containers[0].payload, payload)
    }

    func testOneByteOverFirstMax() throws {
        let splitter = ContainerSplitter(mtu: 247) // firstMax=238
        let payload = Data(repeating: 0xCC, count: 239)
        let containers = try splitter.split(payload, transactionId: 0)

        XCTAssertEqual(containers.count, 2)
        XCTAssertEqual(containers[0].containerType, .first)
        XCTAssertEqual(containers[1].containerType, .subsequent)
        XCTAssertEqual(containers[0].payload.count + containers[1].payload.count, 239)
    }

    func testTransactionIdAutoIncrement() throws {
        let splitter = ContainerSplitter(mtu: 247)
        let payload = Data([0x01])

        let c1 = try splitter.split(payload)
        let c2 = try splitter.split(payload)
        let c3 = try splitter.split(payload)

        XCTAssertEqual(c1[0].transactionId, 0)
        XCTAssertEqual(c2[0].transactionId, 1)
        XCTAssertEqual(c3[0].transactionId, 2)
    }

    func testTransactionIdWraps() throws {
        let splitter = ContainerSplitter(mtu: 247)

        // Use nextTransactionId to advance to 255
        for _ in 0..<255 {
            _ = splitter.nextTransactionId()
        }

        let containers = try splitter.split(Data([0x01]))
        XCTAssertEqual(containers[0].transactionId, 255)

        let containers2 = try splitter.split(Data([0x02]))
        XCTAssertEqual(containers2[0].transactionId, 0)
    }

    func testPayloadTooLargeThrows() {
        let splitter = ContainerSplitter(mtu: 247)
        let payload = Data(repeating: 0xFF, count: 65536)

        XCTAssertThrowsError(try splitter.split(payload)) { error in
            XCTAssertEqual(error as? BlerpcProtocolError, .totalLengthTooLarge)
        }
    }
}
