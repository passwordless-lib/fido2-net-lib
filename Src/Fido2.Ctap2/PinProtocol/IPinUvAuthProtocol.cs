using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// A concrete PIN/UV auth protocol, implementing the platform-side half of the abstract
/// interface defined in §6.5.4 of the CTAP 2.3 Proposed Standard: key agreement, symmetric
/// encryption, and MAC computation used to protect pinUvAuthTokens and authenticate requests.
/// </summary>
public interface IPinUvAuthProtocol
{
    /// <summary>
    /// The numeric identifier passed in the <c>pinUvAuthProtocol</c> parameter of CTAP2 commands
    /// to select this protocol (1 or 2).
    /// </summary>
    int Version { get; }

    /// <summary>
    /// Performs the platform's <c>encapsulate</c> step against the authenticator's public key,
    /// returning the platform key-agreement key to send to the authenticator and the resulting
    /// shared secret.
    /// </summary>
    byte[] GenerateSharedSecret(CredentialPublicKey authenticatorKeyAgreementKey, out CredentialPublicKey platformKeyAgreementKey);

    /// <summary>
    /// <c>encrypt(key, demPlaintext)</c>: encrypts a plaintext (whose length must be a multiple of
    /// the AES block size) using the shared secret as key material.
    /// </summary>
    byte[] Encrypt(byte[] key, ReadOnlySpan<byte> demPlaintext);

    /// <summary>
    /// <c>decrypt(key, demCiphertext)</c>: decrypts a ciphertext produced by <see cref="Encrypt"/>.
    /// </summary>
    byte[] Decrypt(byte[] key, byte[] demCiphertext);

    /// <summary>
    /// <c>authenticate(key, message)</c>: computes a MAC of the given message.
    /// </summary>
    byte[] Authenticate(byte[] key, ReadOnlySpan<byte> message);

    /// <summary>
    /// <c>verify(key, message, signature)</c>: verifies a MAC produced by <see cref="Authenticate"/>.
    /// </summary>
    bool Verify(byte[] key, ReadOnlySpan<byte> message, byte[] signature);
}

/// <summary>
/// Resolves the <see cref="IPinUvAuthProtocol"/> implementation for a given wire-format
/// <c>pinUvAuthProtocol</c> value.
/// </summary>
public static class PinUvAuthProtocol
{
    /// <summary>
    /// Returns the protocol implementation for the given <c>pinUvAuthProtocol</c> version (1 or 2).
    /// </summary>
    public static IPinUvAuthProtocol Select(uint version) => version switch
    {
        1 => PinUvAuthProtocolOne.Instance,
        2 => PinUvAuthProtocolTwo.Instance,
        _ => throw new ArgumentOutOfRangeException(nameof(version), version, "Only PIN/UV auth protocol versions 1 and 2 are defined."),
    };
}
