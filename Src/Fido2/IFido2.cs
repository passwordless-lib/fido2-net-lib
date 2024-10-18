using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

public interface IFido2
{
    AssertionOptions GetAssertionOptions(
        IReadOnlyList<PublicKeyCredentialDescriptor> allowedCredentials,
        UserVerificationRequirement? userVerification,
        AuthenticationExtensionsClientInputs? extensions = null);

    Task<VerifyAssertionResult> MakeAssertionAsync(MakeAssertionParams makeAssertionParams,
        CancellationToken cancellationToken = default);

    Task<RegisteredPublicKeyCredential> MakeNewCredentialAsync(MakeNewCredentialParams makeNewCredentialParams,
        CancellationToken cancellationToken = default);

    CredentialCreateOptions RequestNewCredential(
        Fido2User user,
        IReadOnlyList<PublicKeyCredentialDescriptor> excludeCredentials,
        AuthenticationExtensionsClientInputs? extensions = null);

    CredentialCreateOptions RequestNewCredential(
        Fido2User user,
        IReadOnlyList<PublicKeyCredentialDescriptor> excludeCredentials,
        AuthenticatorSelection authenticatorSelection,
        AttestationConveyancePreference attestationPreference,
        AuthenticationExtensionsClientInputs? extensions = null);
}
