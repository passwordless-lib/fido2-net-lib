using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

public sealed class NegotiateSharedSecretResult
{
    public NegotiateSharedSecretResult(
        CredentialPublicKey authenticatorKey,
        CredentialPublicKey platformKey,
        byte[] sharedShared)
    {
        ArgumentNullException.ThrowIfNull(authenticatorKey);
        ArgumentNullException.ThrowIfNull(platformKey);
        ArgumentNullException.ThrowIfNull(sharedShared);

        AuthenticatorKey = authenticatorKey;
        PlatformKey = platformKey;
        SharedSecret = sharedShared;
    }

    // Fido2 Public Key
    public CredentialPublicKey AuthenticatorKey { get; }

    // Client Public Key
    public CredentialPublicKey PlatformKey { get; }

    public byte[] SharedSecret { get; }
}
