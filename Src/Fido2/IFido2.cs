﻿using System.Collections.Generic;
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

    Task<VerifyAssertionResult> MakeAssertionAsync(
        AuthenticatorAssertionRawResponse assertionResponse,
        AssertionOptions originalOptions,
        byte[] storedPublicKey,
        IReadOnlyList<byte[]> storedDevicePublicKeys,
        uint storedSignatureCounter,
        IsUserHandleOwnerOfCredentialIdAsync isUserHandleOwnerOfCredentialIdCallback,
        byte[]? requestTokenBindingId = null,
        CancellationToken cancellationToken = default);

    Task<RegisteredPublicKeyCredential> MakeNewCredentialAsync(
        AuthenticatorAttestationRawResponse attestationResponse,
        CredentialCreateOptions originalOptions,
        IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUser,
        byte[]? requestTokenBindingId = null,
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
