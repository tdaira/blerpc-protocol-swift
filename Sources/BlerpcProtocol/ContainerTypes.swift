import Foundation

/// Container type encoded in bits 7-6 of the flags byte.
public enum ContainerType: UInt8 {
    case first = 0x00
    case subsequent = 0x01
    case control = 0x03
}

/// Control command encoded in bits 5-2 of the flags byte.
public enum ControlCmd: UInt8 {
    case none = 0x00
    case timeout = 0x01
    case streamEndC2P = 0x02
    case streamEndP2C = 0x03
    case capabilities = 0x04
    case error = 0x05
    case keyExchange = 0x06
}

public let firstHeaderSize = 6
public let subsequentHeaderSize = 4
public let controlHeaderSize = 4
public let attOverhead = 3
public let blerpcErrorResponseTooLarge: UInt8 = 0x01
public let capabilityFlagEncryptionSupported: UInt16 = 0x0001
