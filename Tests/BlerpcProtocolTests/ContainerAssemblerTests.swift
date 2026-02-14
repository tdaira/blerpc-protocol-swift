import XCTest
@testable import BlerpcProtocol

final class ContainerAssemblerTests: XCTestCase {
    func testSingleContainerAssembly() {
        let assembler = ContainerAssembler()
        let container = Container(
            transactionId: 0,
            sequenceNumber: 0,
            containerType: .first,
            totalLength: 3,
            payload: Data([0x01, 0x02, 0x03])
        )
        let result = assembler.feed(container)
        XCTAssertEqual(result, Data([0x01, 0x02, 0x03]))
    }

    func testMultiContainerAssembly() {
        let assembler = ContainerAssembler()

        let first = Container(
            transactionId: 0,
            sequenceNumber: 0,
            containerType: .first,
            totalLength: 5,
            payload: Data([0x01, 0x02])
        )
        XCTAssertNil(assembler.feed(first))

        let subsequent = Container(
            transactionId: 0,
            sequenceNumber: 1,
            containerType: .subsequent,
            payload: Data([0x03, 0x04, 0x05])
        )
        let result = assembler.feed(subsequent)
        XCTAssertEqual(result, Data([0x01, 0x02, 0x03, 0x04, 0x05]))
    }

    func testSequenceGapDiscards() {
        let assembler = ContainerAssembler()

        let first = Container(
            transactionId: 0,
            sequenceNumber: 0,
            containerType: .first,
            totalLength: 10,
            payload: Data([0x01, 0x02])
        )
        XCTAssertNil(assembler.feed(first))

        // Skip seq 1, send seq 2
        let bad = Container(
            transactionId: 0,
            sequenceNumber: 2,
            containerType: .subsequent,
            payload: Data([0x03, 0x04])
        )
        XCTAssertNil(assembler.feed(bad))

        // Transaction should be discarded; seq 1 should also return nil
        let late = Container(
            transactionId: 0,
            sequenceNumber: 1,
            containerType: .subsequent,
            payload: Data([0x05])
        )
        XCTAssertNil(assembler.feed(late))
    }

    func testControlContainerIgnored() {
        let assembler = ContainerAssembler()
        let control = Container(
            transactionId: 0,
            sequenceNumber: 0,
            containerType: .control,
            controlCmd: .timeout,
            payload: Data([0x64, 0x00])
        )
        XCTAssertNil(assembler.feed(control))
    }

    func testOrphanedSubsequentIgnored() {
        let assembler = ContainerAssembler()
        let subsequent = Container(
            transactionId: 99,
            sequenceNumber: 1,
            containerType: .subsequent,
            payload: Data([0x01])
        )
        XCTAssertNil(assembler.feed(subsequent))
    }

    func testSplitAndAssembleSmall() throws {
        let splitter = ContainerSplitter(mtu: 27) // Small MTU
        let assembler = ContainerAssembler()
        let payload = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B])

        let containers = try splitter.split(payload, transactionId: 0)
        var result: Data?
        for c in containers {
            result = assembler.feed(c)
        }
        XCTAssertEqual(result, payload)
    }

    func testSplitAndAssembleLarge() throws {
        let splitter = ContainerSplitter(mtu: 27)
        let assembler = ContainerAssembler()
        let payload = Data(repeating: 0xCC, count: 1024)

        let containers = try splitter.split(payload, transactionId: 5)
        var result: Data?
        for c in containers {
            result = assembler.feed(c)
        }
        XCTAssertNotNil(result)
        XCTAssertEqual(result, payload)
    }

    func testSplitAndAssembleVeryLarge() throws {
        let splitter = ContainerSplitter(mtu: 247)
        let assembler = ContainerAssembler()
        let payload = Data((0..<60000).map { UInt8($0 & 0xFF) })

        let containers = try splitter.split(payload, transactionId: 10)
        var result: Data?
        for c in containers {
            result = assembler.feed(c)
        }
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.count, 60000)
        XCTAssertEqual(result, payload)
    }

    func testEmptyPayload() {
        let assembler = ContainerAssembler()
        let container = Container(
            transactionId: 0,
            sequenceNumber: 0,
            containerType: .first,
            totalLength: 0,
            payload: Data()
        )
        let result = assembler.feed(container)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.count, 0)
    }
}
