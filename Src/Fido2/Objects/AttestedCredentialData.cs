#nullable disable

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

using Fido2NetLib.Exceptions;

namespace Fido2NetLib.Objects;

public sealed class AttestedCredentialData
{
    /// <summary>
    /// Minimum length of the attested credential data structure.  AAGUID + credentialID length + credential ID + credential public key.
    /// <see cref="https://www.w3.org/TR/webauthn/#attested-credential-data"/>
    /// </summary>
    private static readonly int _minLength = Marshal.SizeOf<Guid>() + sizeof(ushort) + sizeof(byte) + sizeof(byte);

    /// <summary>
    /// Instantiates an AttestedCredentialData object from an aaguid, credentialID, and CredentialPublicKey
    /// </summary>
    /// <param name="aaguid"></param>
    /// <param name="credentialID"></param>
    /// <param name="cpk"></param>
    public AttestedCredentialData(Guid aaguid, byte[] credentialID, CredentialPublicKey cpk)
    {
        AaGuid = aaguid;
        CredentialID = credentialID;
        CredentialPublicKey = cpk;
    }

    /// <summary>
    /// Decodes attested credential data.
    /// </summary>
    public AttestedCredentialData(byte[] data)
        : this(data, out _)
    {
    }

    internal AttestedCredentialData(ReadOnlyMemory<byte> data, out int bytesRead)
    {
        if (data.Length < _minLength)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestedCredentialData, Fido2ErrorMessages.InvalidAttestedCredentialData_TooShort);

        int position = 0;

        // First 16 bytes is AAGUID
        var aaguidBytes = data[..16];

        position += 16;

        if (BitConverter.IsLittleEndian)
        {
            // GUID from authenticator is big endian. If we are on a little endian system, convert.
            AaGuid = FromBigEndian(aaguidBytes.ToArray());
        }
        else
        {
            AaGuid = new Guid(aaguidBytes.Span);
        }

        // Byte length of Credential ID, 16-bit unsigned big-endian integer. 
        var credentialIDLen = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(position, 2).Span);

        position += 2;

        // Read the credential ID bytes
        CredentialID = data.Slice(position, credentialIDLen).ToArray();

        position += credentialIDLen;

        // "Determining attested credential data's length, which is variable, involves determining 
        // credentialPublicKey's beginning location given the preceding credentialId's length, and 
        // then determining the credentialPublicKey's length"


        // Read the CBOR object from the stream
        CredentialPublicKey = CredentialPublicKey.Decode(data[position..], out int read);

        position += read;

        bytesRead = position;
    }

    /// <summary>
    /// The AAGUID of the authenticator. Can be used to identify the make and model of the authenticator.
    /// <see cref="https://www.w3.org/TR/webauthn/#aaguid"/>
    /// </summary>
    public Guid AaGuid { get; private set; }

    /// <summary>
    /// A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
    /// <see cref="https://www.w3.org/TR/webauthn/#credential-id"/>
    /// </summary>
    public byte[] CredentialID { get; private set; }

    /// <summary>
    /// The credential public key encoded in COSE_Key format, as defined in 
    /// Section 7 of RFC8152, using the CTAP2 canonical CBOR encoding form.
    /// <see cref="https://www.w3.org/TR/webauthn/#credential-public-key"/>
    /// </summary>
    public CredentialPublicKey CredentialPublicKey { get; private set; }

    private static void SwapBytes(byte[] bytes, int index1, int index2)
    {
        var temp = bytes[index1];
        bytes[index1] = bytes[index2];
        bytes[index2] = temp;
    }

    /// <summary>
    /// AAGUID is sent as big endian byte array, this converter is for little endian systems.
    /// </summary>
    public static Guid FromBigEndian(byte[] aaGuid)
    {
        SwapBytes(aaGuid, 0, 3);
        SwapBytes(aaGuid, 1, 2);
        SwapBytes(aaGuid, 4, 5);
        SwapBytes(aaGuid, 6, 7);

        return new Guid(aaGuid);
    }

    /// <summary>
    /// AAGUID is sent as big endian byte array, this converter is for little endian systems.
    /// </summary>
    public static byte[] AaGuidToBigEndian(Guid aaGuid)
    {
        var aaguid = aaGuid.ToByteArray();

        SwapBytes(aaguid, 0, 3);
        SwapBytes(aaguid, 1, 2);
        SwapBytes(aaguid, 4, 5);
        SwapBytes(aaguid, 6, 7);

        return aaguid;
    }

    public override string ToString()
    {
        return $"AAGUID: {AaGuid}, CredentialID: {Convert.ToHexString(CredentialID)}, CredentialPublicKey: {CredentialPublicKey}";
    }

    public byte[] ToByteArray()
    {
        var writer = new ArrayBufferWriter<byte>(16 + 2 + CredentialID.Length + 512);

        WriteTo(writer);

        return writer.WrittenSpan.ToArray();
    }

    public void WriteTo(IBufferWriter<byte> writer)
    {
        // Write the aaguid as big endian bytes
        if (BitConverter.IsLittleEndian)
        {
            writer.Write(AaGuidToBigEndian(AaGuid));
        }
        else
        {
            _ = AaGuid.TryWriteBytes(writer.GetSpan(16));
            writer.Advance(16);
        }

        // Write the length of credential ID, as big endian bytes of a 16-bit unsigned integer
        writer.WriteUInt16BigEndian((ushort)CredentialID.Length);

        // Write CredentialID bytes
        writer.Write(CredentialID);

        // Write credential public key bytes
        writer.Write(CredentialPublicKey.GetBytes());
    }
}
