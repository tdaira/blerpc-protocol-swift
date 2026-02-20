import Foundation

/// Command type: request from central or response from peripheral.
public enum CommandType: UInt8 {
    case request = 0
    case response = 1
}

/// A bleRPC command packet with a type, command name, and protobuf data.
///
/// Command packets are the application-level messages that ride inside
/// the container layer's reassembled payloads.
public struct CommandPacket: Equatable {
    public let cmdType: CommandType
    public let cmdName: String
    public let data: Data

    public init(cmdType: CommandType, cmdName: String, data: Data = Data()) {
        self.cmdType = cmdType
        self.cmdName = cmdName
        self.data = data
    }

    /// Serialize this command packet to its binary wire format.
    public func serialize() throws -> Data {
        guard !cmdName.isEmpty else {
            throw BlerpcProtocolError.cmdNameEmpty
        }

        let nameBytes = Array(cmdName.utf8)
        guard nameBytes.count <= 255 else {
            throw BlerpcProtocolError.cmdNameTooLong
        }
        guard data.count <= 65535 else {
            throw BlerpcProtocolError.dataTooLargeForCommand
        }

        var result = Data(capacity: 2 + nameBytes.count + 2 + data.count)
        result.append(cmdType.rawValue << 7)
        result.append(UInt8(nameBytes.count))
        result.append(contentsOf: nameBytes)
        result.append(UInt8(data.count & 0xFF))
        result.append(UInt8(data.count >> 8))
        result.append(data)
        return result
    }

    /// Deserialize a command packet from its binary wire format.
    public static func deserialize(_ data: Data) throws -> CommandPacket {
        guard data.count >= 2 else {
            throw BlerpcProtocolError.dataTooShort(data.count)
        }

        let typeByte = data[data.startIndex]
        let typeRaw = typeByte >> 7
        guard let cmdType = CommandType(rawValue: typeRaw) else {
            throw BlerpcProtocolError.unknownCommandType(typeRaw)
        }

        let nameLen = Int(data[data.startIndex + 1])
        guard data.count >= 2 + nameLen + 2 else {
            throw BlerpcProtocolError.dataTooShort(data.count)
        }

        let nameData = data.subdata(in: (data.startIndex + 2)..<(data.startIndex + 2 + nameLen))
        guard let cmdName = String(data: nameData, encoding: .utf8) else {
            throw BlerpcProtocolError.dataTooShort(data.count)
        }

        let dataLenOffset = data.startIndex + 2 + nameLen
        let dataLen = Int(data[dataLenOffset]) | (Int(data[dataLenOffset + 1]) << 8)

        let payloadStart = dataLenOffset + 2
        guard data.count >= payloadStart + dataLen else {
            throw BlerpcProtocolError.dataTooShort(data.count)
        }
        let payload = data.subdata(in: payloadStart..<(payloadStart + dataLen))

        return CommandPacket(cmdType: cmdType, cmdName: cmdName, data: payload)
    }
}
