import Foundation

public enum BlerpcProtocolError: Error, Equatable {
    case dataTooShort(Int)
    case unknownContainerType(UInt8)
    case payloadTooLarge
    case totalLengthTooLarge
    case tooManyContainers
    case cmdNameTooLong
    case cmdNameEmpty
    case dataTooLargeForCommand
    case unknownCommandType(UInt8)
}

public struct Container: Equatable {
    public let transactionId: UInt8
    public let sequenceNumber: UInt8
    public let containerType: ContainerType
    public let controlCmd: ControlCmd
    public let totalLength: UInt16
    public let payload: Data

    public init(
        transactionId: UInt8,
        sequenceNumber: UInt8,
        containerType: ContainerType,
        controlCmd: ControlCmd = .none,
        totalLength: UInt16 = 0,
        payload: Data = Data()
    ) {
        self.transactionId = transactionId
        self.sequenceNumber = sequenceNumber
        self.containerType = containerType
        self.controlCmd = controlCmd
        self.totalLength = totalLength
        self.payload = payload
    }

    public func serialize() -> Data {
        let flags = (containerType.rawValue << 6) | (controlCmd.rawValue << 2)

        if containerType == .first {
            var result = Data(capacity: firstHeaderSize + payload.count)
            result.append(transactionId)
            result.append(sequenceNumber)
            result.append(flags)
            result.append(UInt8(totalLength & 0xFF))
            result.append(UInt8(totalLength >> 8))
            result.append(UInt8(payload.count))
            result.append(payload)
            return result
        } else {
            var result = Data(capacity: subsequentHeaderSize + payload.count)
            result.append(transactionId)
            result.append(sequenceNumber)
            result.append(flags)
            result.append(UInt8(payload.count))
            result.append(payload)
            return result
        }
    }

    public static func deserialize(_ data: Data) throws -> Container {
        guard data.count >= 3 else {
            throw BlerpcProtocolError.dataTooShort(data.count)
        }

        let transactionId = data[data.startIndex]
        let sequenceNumber = data[data.startIndex + 1]
        let flags = data[data.startIndex + 2]

        let typeRaw = flags >> 6
        guard let containerType = ContainerType(rawValue: typeRaw) else {
            throw BlerpcProtocolError.unknownContainerType(typeRaw)
        }

        let cmdRaw = (flags >> 2) & 0x0F
        let controlCmd = ControlCmd(rawValue: cmdRaw) ?? .none

        if containerType == .first {
            guard data.count >= firstHeaderSize else {
                throw BlerpcProtocolError.dataTooShort(data.count)
            }
            let base = data.startIndex
            let totalLength = UInt16(data[base + 3]) | (UInt16(data[base + 4]) << 8)
            let payloadLength = Int(data[base + 5])
            let payloadStart = base + firstHeaderSize
            guard data.count >= payloadStart + payloadLength else {
                throw BlerpcProtocolError.dataTooShort(data.count)
            }
            let payload = data.subdata(in: payloadStart..<(payloadStart + payloadLength))
            return Container(
                transactionId: transactionId,
                sequenceNumber: sequenceNumber,
                containerType: containerType,
                controlCmd: controlCmd,
                totalLength: totalLength,
                payload: payload
            )
        } else {
            guard data.count >= subsequentHeaderSize else {
                throw BlerpcProtocolError.dataTooShort(data.count)
            }
            let payloadLength = Int(data[data.startIndex + 3])
            let payloadStart = data.startIndex + subsequentHeaderSize
            guard data.count >= payloadStart + payloadLength else {
                throw BlerpcProtocolError.dataTooShort(data.count)
            }
            let payload = data.subdata(in: payloadStart..<(payloadStart + payloadLength))
            return Container(
                transactionId: transactionId,
                sequenceNumber: sequenceNumber,
                containerType: containerType,
                controlCmd: controlCmd,
                payload: payload
            )
        }
    }
}
