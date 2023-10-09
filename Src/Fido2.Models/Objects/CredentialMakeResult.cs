#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fido2NetLib.Objects;

/// <summary>
/// Result of parsing and verifying attestation. Used to transport Public Key back to RP
/// </summary>
public sealed class CredentialMakeResult : Fido2ResponseBase
{
    public CredentialMakeResult(string status, string errorMessage, RegisteredPublicKeyCredential? result)
    {
        Status = status;
        ErrorMessage = errorMessage;
        Result = result;
    }

    public RegisteredPublicKeyCredential? Result { get; }

    // todo: add debuginfo?
}
