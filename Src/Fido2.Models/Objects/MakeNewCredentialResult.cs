#nullable enable

namespace Fido2NetLib.Objects;

/// <summary>
/// Result of parsing and verifying attestation. Used to transport Public Key back to RP.
/// </summary>
public sealed class MakeNewCredentialResult : Fido2ResponseBase
{
    public MakeNewCredentialResult(string status, string errorMessage, RegisteredPublicKeyCredential? result)
    {
        Status = status;
        ErrorMessage = errorMessage;
        Result = result;
    }

    public RegisteredPublicKeyCredential? Result { get; }

    // todo: add debuginfo?
}
