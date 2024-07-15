#nullable enable

namespace Fido2NetLib.Objects;

/// <summary>
/// Result of parsing and verifying attestation. Used to transport Public Key back to RP.
/// </summary>
public sealed class MakeNewCredentialResult(RegisteredPublicKeyCredential result)
{
    public RegisteredPublicKeyCredential Result { get; } = result;

    // todo: add debuginfo?
}
