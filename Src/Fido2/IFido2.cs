using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

public interface IFido2
{
    AssertionOptions GetAssertionOptions(GetAssertionOptionsParams getAssertionOptionsParams);

    Task<VerifyAssertionResult> MakeAssertionAsync(MakeAssertionParams makeAssertionParams,
        CancellationToken cancellationToken = default);

    Task<RegisteredPublicKeyCredential> MakeNewCredentialAsync(MakeNewCredentialParams makeNewCredentialParams,
        CancellationToken cancellationToken = default);

    CredentialCreateOptions RequestNewCredential(RequestNewCredentialParams requestNewCredentialParams);

    /// <inheritdoc cref="Fido2.GetUnknownCredentialOptions"/>
    UnknownCredentialOptions GetUnknownCredentialOptions(byte[] credentialId);

    /// <inheritdoc cref="Fido2.GetAllAcceptedCredentialsOptions"/>
    AllAcceptedCredentialsOptions GetAllAcceptedCredentialsOptions(byte[] userId, IReadOnlyList<byte[]> allAcceptedCredentialIds);

    /// <inheritdoc cref="Fido2.GetCurrentUserDetailsOptions"/>
    CurrentUserDetailsOptions GetCurrentUserDetailsOptions(Fido2User user);
}
