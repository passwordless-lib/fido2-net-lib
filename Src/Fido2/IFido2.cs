using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{
    public interface IFido2
    {
        PublicKeyCredentialRequestOptions GetAssertionOptions(
            IEnumerable<PublicKeyCredentialDescriptor> allowedCredentials, 
            UserVerificationRequirement? userVerification = UserVerificationRequirement.Preferred, 
            AuthenticationExtensionsClientInputs? extensions = null);

        Task<AssertionVerificationResult> MakeAssertionAsync(
            AuthenticatorAssertionRawResponse assertionResponse,
            PublicKeyCredentialRequestOptions originalOptions,
            byte[] storedPublicKey,
            uint storedSignatureCounter,
            IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredentialIdCallback,
            CancellationToken cancellationToken = default);

        Task<Fido2.CredentialMakeResult> MakeNewCredentialAsync(
            AuthenticatorAttestationRawResponse attestationResponse,
            PublicKeyCredentialCreationOptions origChallenge,
            IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUser,
            CancellationToken cancellationToken = default);

        PublicKeyCredentialCreationOptions RequestNewCredential(
            Fido2User user,
            List<PublicKeyCredentialDescriptor> excludeCredentials,
            AuthenticationExtensionsClientInputs? extensions = null);

        PublicKeyCredentialCreationOptions RequestNewCredential(
            Fido2User user,
            List<PublicKeyCredentialDescriptor> excludeCredentials,
            AuthenticatorSelectionCriteria authenticatorSelection,
            AttestationConveyancePreference attestationPreference,
            AuthenticationExtensionsClientInputs? extensions = null);
    }
}
