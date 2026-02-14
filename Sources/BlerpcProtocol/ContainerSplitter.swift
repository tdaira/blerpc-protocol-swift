import Foundation

public class ContainerSplitter {
    public let mtu: Int
    public var effectiveMtu: Int { mtu - attOverhead }
    private var transactionIdCounter: UInt8 = 0

    public init(mtu: Int = 247) {
        self.mtu = mtu
    }

    public func nextTransactionId() -> UInt8 {
        let tid = transactionIdCounter
        transactionIdCounter = transactionIdCounter &+ 1
        return tid
    }

    public func split(_ payload: Data, transactionId: UInt8? = nil) throws -> [Container] {
        guard payload.count <= 65535 else {
            throw BlerpcProtocolError.totalLengthTooLarge
        }

        let tid = transactionId ?? nextTransactionId()
        let firstMaxPayload = effectiveMtu - firstHeaderSize
        let subsequentMaxPayload = effectiveMtu - subsequentHeaderSize

        var containers: [Container] = []
        var offset = 0
        var seq: UInt8 = 0

        // First container
        let firstPayloadSize = min(payload.count, firstMaxPayload)
        let firstPayload = payload.prefix(firstPayloadSize)
        containers.append(Container(
            transactionId: tid,
            sequenceNumber: seq,
            containerType: .first,
            totalLength: UInt16(payload.count),
            payload: Data(firstPayload)
        ))
        offset = firstPayloadSize
        seq = 1

        // Subsequent containers
        while offset < payload.count {
            guard seq > 0 else {
                // seq wrapped around to 0, too many containers
                throw BlerpcProtocolError.tooManyContainers
            }
            let chunkSize = min(payload.count - offset, subsequentMaxPayload)
            let chunk = payload.subdata(in: offset..<(offset + chunkSize))
            containers.append(Container(
                transactionId: tid,
                sequenceNumber: seq,
                containerType: .subsequent,
                payload: chunk
            ))
            offset += chunkSize
            seq = seq &+ 1
            if seq == 0 && offset < payload.count {
                throw BlerpcProtocolError.tooManyContainers
            }
        }

        return containers
    }
}
