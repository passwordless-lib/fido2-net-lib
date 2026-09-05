using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// The authenticator extension input for the <c>hmac-secret</c> extension (§12.7 of the CTAP 2.3
/// Proposed Standard) as sent in an authenticatorGetAssertion request, and for the
/// <c>hmac-secret-mc</c> extension (§12.8) as sent in an authenticatorMakeCredential request
/// (which reuses this exact structure).
/// </summary>
public sealed class HmacSecretInput
{
    private HmacSecretInput(CredentialPublicKey keyAgreement, byte[] saltEnc, byte[] saltAuth, uint? pinUvAuthProtocol)
    {
        KeyAgreement = keyAgreement;
        SaltEnc = saltEnc;
        SaltAuth = saltAuth;
        PinUvAuthProtocol = pinUvAuthProtocol;
    }

    /// <summary>The platform key-agreement key.</summary>
    public CredentialPublicKey KeyAgreement { get; }

    /// <summary>
    /// <c>encrypt(sharedSecret, salt1)</c>, or <c>encrypt(sharedSecret, salt1 || salt2)</c> when a
    /// second salt is supplied.
    /// </summary>
    public byte[] SaltEnc { get; }

    /// <summary><c>authenticate(sharedSecret, saltEnc)</c>.</summary>
    public byte[] SaltAuth { get; }

    /// <summary>
    /// The PIN/UV auth protocol version <see cref="SaltEnc"/>/<see cref="SaltAuth"/> were computed
    /// with. CTAP 2.1+ platforms MUST include this if it is not 1.
    /// </summary>
    public uint? PinUvAuthProtocol { get; }

    /// <summary>
    /// Builds an <see cref="HmacSecretInput"/> by encrypting and authenticating one or two 32-byte
    /// salts with the given shared secret, per §12.7.
    /// </summary>
    /// <param name="platformKey">The platform key-agreement key returned by <c>NegotiateSharedSecretAsync</c>.</param>
    /// <param name="sharedSecret">The shared secret returned by <c>NegotiateSharedSecretAsync</c>.</param>
    /// <param name="salt1">The first 32-byte salt.</param>
    /// <param name="salt2">An optional second 32-byte salt, used to roll over the secret in one operation.</param>
    /// <param name="protocol">The PIN/UV auth protocol <paramref name="sharedSecret"/> was negotiated with. Defaults to <see cref="PinUvAuthProtocolOne"/>.</param>
    public static HmacSecretInput Create(
        CredentialPublicKey platformKey,
        byte[] sharedSecret,
        byte[] salt1,
        byte[]? salt2 = null,
        IPinUvAuthProtocol? protocol = null)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(salt1.Length, 32, nameof(salt1));

        if (salt2 != null)
        {
            ArgumentOutOfRangeException.ThrowIfNotEqual(salt2.Length, 32, nameof(salt2));
        }

        protocol ??= PinUvAuthProtocolOne.Instance;

        byte[] salts = salt2 is null ? salt1 : [.. salt1, .. salt2];

        byte[] saltEnc = protocol.Encrypt(sharedSecret, salts);
        byte[] saltAuth = protocol.Authenticate(sharedSecret, saltEnc);

        return new HmacSecretInput(platformKey, saltEnc, saltAuth, (uint)protocol.Version);
    }

    internal CborMap ToCborObject()
    {
        var result = new CborMap
        {
            { 0x01, KeyAgreement.GetCborObject() },
            { 0x02, SaltEnc },
            { 0x03, SaltAuth }
        };

        if (PinUvAuthProtocol.HasValue)
        {
            result.Add(0x04, (int)PinUvAuthProtocol.Value);
        }

        return result;
    }
}

/// <summary>
/// Helpers for decrypting the <c>hmac-secret</c> extension's authenticator extension output
/// (§12.7), found in the <c>extensions</c> field of the authenticator data.
/// </summary>
public static class HmacSecretOutput
{
    /// <summary>
    /// Decrypts the <c>hmac-secret</c> output, returning <c>output1</c> and, if two salts were
    /// requested, <c>output2</c>.
    /// </summary>
    /// <param name="sharedSecret">The shared secret the corresponding <see cref="HmacSecretInput"/> was built with.</param>
    /// <param name="encryptedOutput">The raw bytes of the <c>hmac-secret</c> entry in the authenticator data's extensions map.</param>
    /// <param name="protocol">The PIN/UV auth protocol <paramref name="sharedSecret"/> was negotiated with. Defaults to <see cref="PinUvAuthProtocolOne"/>.</param>
    public static (byte[] Output1, byte[]? Output2) Decrypt(byte[] sharedSecret, byte[] encryptedOutput, IPinUvAuthProtocol? protocol = null)
    {
        protocol ??= PinUvAuthProtocolOne.Instance;

        byte[] plaintext = protocol.Decrypt(sharedSecret, encryptedOutput);

        if (plaintext.Length is not (32 or 64))
        {
            throw new ArgumentException("Decrypted hmac-secret output must be 32 or 64 bytes.", nameof(encryptedOutput));
        }

        byte[] output1 = plaintext[..32];
        byte[]? output2 = plaintext.Length == 64 ? plaintext[32..] : null;

        return (output1, output2);
    }
}
