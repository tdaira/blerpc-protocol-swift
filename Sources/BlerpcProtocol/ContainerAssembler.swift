import Foundation

/// Reassembles fragmented containers back into complete payloads.
///
/// Feed incoming containers via ``feed(_:)``; when all fragments of a
/// transaction have arrived, the complete payload is returned.
public class ContainerAssembler {
    private struct AssemblyState {
        let totalLength: Int
        var expectedSeq: UInt8
        var fragments: [Data]
        var receivedLength: Int
    }

    private var transactions: [UInt8: AssemblyState] = [:]

    public init() {}

    /// Feed a received container into the assembler.
    ///
    /// - Returns: The complete reassembled payload when all fragments have arrived, or nil.
    public func feed(_ container: Container) -> Data? {
        if container.containerType == .control {
            return nil
        }

        if container.containerType == .first {
            let totalLength = Int(container.totalLength)
            var state = AssemblyState(
                totalLength: totalLength,
                expectedSeq: 1,
                fragments: [container.payload],
                receivedLength: container.payload.count
            )

            if state.receivedLength >= totalLength {
                transactions.removeValue(forKey: container.transactionId)
                return assemblePayload(&state)
            }

            transactions[container.transactionId] = state
            return nil
        }

        // SUBSEQUENT
        guard var state = transactions[container.transactionId] else {
            return nil
        }

        if container.sequenceNumber != state.expectedSeq {
            transactions.removeValue(forKey: container.transactionId)
            return nil
        }

        state.fragments.append(container.payload)
        state.receivedLength += container.payload.count
        state.expectedSeq = state.expectedSeq &+ 1

        if state.receivedLength >= state.totalLength {
            transactions.removeValue(forKey: container.transactionId)
            return assemblePayload(&state)
        }

        transactions[container.transactionId] = state
        return nil
    }

    /// Clear all in-progress assembly state.
    public func reset() {
        transactions.removeAll()
    }

    private func assemblePayload(_ state: inout AssemblyState) -> Data {
        var result = Data(capacity: state.totalLength)
        for fragment in state.fragments {
            result.append(fragment)
        }
        return result.prefix(state.totalLength)
    }
}
