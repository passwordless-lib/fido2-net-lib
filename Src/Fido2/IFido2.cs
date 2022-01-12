using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{
    public interface IFido2
    {
        AssertionOptions GetAssertionOptions(
            IEnumerable<PublicKeyCredentialDescriptor> allowedCredentials, 
            UserVerificationRequirement? userVerification, 
            AuthenticationExtensionsClientInputs? extensions = null);

        Task<AssertionVerificationResult> MakeAssertionAsync(
            AuthenticatorAssertionRawResponse assertionResponse,
            AssertionOptions originalOptions,
            byte[] storedPublicKey,
            uint storedSignatureCounter,
            IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredentialIdCallback,
            byte[]? requestTokenBindingId = null,
            CancellationToken cancellationToken = default);

        Task<Fido2.CredentialMakeResult> MakeNewCredentialAsync(
            AuthenticatorAttestationRawResponse attestationResponse,
            CredentialCreateOptions origChallenge,
            IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUser,
            byte[]? requestTokenBindingId = null,
            CancellationToken cancellationToken = default);

        CredentialCreateOptions RequestNewCredential(
            Fido2User user,
            List<PublicKeyCredentialDescriptor> excludeCredentials,
            AuthenticationExtensionsClientInputs? extensions = null);

        CredentialCreateOptions RequestNewCredential(
            Fido2User user,
            List<PublicKeyCredentialDescriptor> excludeCredentials,
            AuthenticatorSelection authenticatorSelection,
            AttestationConveyancePreference attestationPreference,
            AuthenticationExtensionsClientInputs? extensions = null);
    }
}
