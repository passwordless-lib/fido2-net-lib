using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// Request for the authenticatorLargeBlobs (0x0C) command, used to read or write fragments of the
/// authenticator's serialized large-blob array.
/// <para>New in CTAP 2.1 (see §6.10.2 of the CTAP 2.3 Proposed Standard).</para>
/// </summary>
public sealed class AuthenticatorLargeBlobsCommand(
    uint offset,
    int? get = null,
    byte[]? set = null,
    int? length = null,
    byte[]? pinUvAuthParam = null,
    uint? pinUvAuthProtocol = null) : CtapCommand
{
    /// <summary>
    /// The number of bytes requested to read. MUST NOT be present if <see cref="Set"/> is present.
    /// </summary>
    [CborMember(0x01)]
    public int? Get { get; } = get;

    /// <summary>
    /// A fragment to write. MUST NOT be present if <see cref="Get"/> is present.
    /// </summary>
    [CborMember(0x02)]
    public byte[]? Set { get; } = set;

    /// <summary>
    /// The byte offset at which to read/write.
    /// </summary>
    [CborMember(0x03)]
    public uint Offset { get; } = offset;

    /// <summary>
    /// The total length of a write operation. Present if, and only if, <see cref="Set"/> is present and <see cref="Offset"/> is zero.
    /// </summary>
    [CborMember(0x04)]
    public int? Length { get; } = length;

    /// <summary>
    /// <c>authenticate(pinUvAuthToken, 32×0xff || h'0c00' || uint32LittleEndian(offset) || SHA-256(contents of the set byte string))</c>.
    /// Only relevant, and required, for non-initial write fragments when the authenticator requires user verification.
    /// </summary>
    [CborMember(0x05)]
    public byte[]? PinUvAuthParam { get; } = pinUvAuthParam;

    /// <summary>
    /// PIN/UV protocol version chosen by the platform.
    /// </summary>
    [CborMember(0x06)]
    public uint? PinUvAuthProtocol { get; } = pinUvAuthProtocol;

    public override CtapCommandType Type => CtapCommandType.AuthenticatorLargeBlobs;

    protected override CborObject? GetParameters()
    {
        var cbor = new CborMap();

        if (Get.HasValue)
        {
            cbor.Add(0x01, Get.Value);
        }

        if (Set != null)
        {
            cbor.Add(0x02, Set);
        }

        cbor.Add(0x03, (long)Offset);

        if (Length.HasValue)
        {
            cbor.Add(0x04, Length.Value);
        }

        if (PinUvAuthParam != null)
        {
            cbor.Add(0x05, PinUvAuthParam);
        }

        if (PinUvAuthProtocol.HasValue)
        {
            cbor.Add(0x06, (int)PinUvAuthProtocol.Value);
        }

        return cbor;
    }
}
