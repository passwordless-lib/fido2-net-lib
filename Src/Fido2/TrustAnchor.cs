using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

public static class TrustAnchor
{
    public static void Verify(MetadataBLOBPayloadEntry? metadataEntry, X509Certificate2[] trustPath, FidoValidationMode validationMode = FidoValidationMode.Default)
    {
        Verify(metadataEntry, trustPath, attestationType: null, validationMode);
    }

    /// <summary>
    /// Checks the attestation trust path, and the kind of attestation that produced it, against the
    /// authenticator model's metadata statement. Nothing is checked when there is no metadata for the model.
    /// </summary>
    /// <param name="metadataEntry">The model's metadata, or <see langword="null"/> when it has none.</param>
    /// <param name="trustPath">The trust path the attestation statement's verification procedure returned, or <see langword="null"/> for self or no attestation.</param>
    /// <param name="attestationType">The attestation type that procedure established, or <see langword="null"/> to check the trust path alone.</param>
    /// <param name="validationMode">How strictly to validate.</param>
    public static void Verify(MetadataBLOBPayloadEntry? metadataEntry, X509Certificate2[]? trustPath, AttestationType? attestationType, FidoValidationMode validationMode = FidoValidationMode.Default)
    {
        if (metadataEntry?.MetadataStatement?.AttestationTypes is null)
            return;

        static bool ContainsAttestationType(MetadataBLOBPayloadEntry entry, MetadataAttestationType type)
        {
            return entry.MetadataStatement.AttestationTypes.Contains(type.ToEnumMemberValue());
        }

        // Self attestation is signed with the credential key itself, so it proves nothing about which
        // authenticator made the credential, and the AAGUID it carries is whatever the client chose to send.
        // A model whose metadata does not declare basic_surrogate never produces it; the claim to be that
        // model is therefore false, and the registration is refused rather than recorded under its AAGUID.
        if (AttestationType.Self.Equals(attestationType) && !ContainsAttestationType(metadataEntry, MetadataAttestationType.ATTESTATION_BASIC_SURROGATE))
        {
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, Fido2ErrorMessages.SelfAttestationNotDeclaredInMetadata);
        }

        if (trustPath != null)
        {
            // If the authenticator's metadata requires basic full attestation, build and verify the chain
            if (ContainsAttestationType(metadataEntry, MetadataAttestationType.ATTESTATION_BASIC_FULL) ||
                ContainsAttestationType(metadataEntry, MetadataAttestationType.ATTESTATION_PRIVACY_CA))
            {
                string[] certStrings = metadataEntry.MetadataStatement.AttestationRootCertificates;
                var attestationRootCertificates = new X509Certificate2[certStrings.Length];

                for (int i = 0; i < attestationRootCertificates.Length; i++)
                {
                    attestationRootCertificates[i] = X509CertificateHelper.CreateFromRawData(Convert.FromBase64String(certStrings[i]));
                }

                if (trustPath.Length > 1 && attestationRootCertificates.Any(c => string.Equals(c.Thumbprint, trustPath[^1].Thumbprint, StringComparison.Ordinal)))
                {
                    throw new Fido2VerificationException(Fido2ErrorMessages.InvalidCertificateChain);
                }

                if (!CryptoUtils.ValidateTrustChain(trustPath, attestationRootCertificates, validationMode))
                {
                    throw new Fido2VerificationException(Fido2ErrorMessages.InvalidCertificateChain);
                }
            }

            else if (ContainsAttestationType(metadataEntry, MetadataAttestationType.ATTESTATION_ANONCA))
            {
                // skip verification for Anonymization CA (AnonCA)
            }
            else // otherwise, ensure the certificate is self signed
            {
                var trustPath0 = trustPath[0];

                if (!string.Equals(trustPath0.Subject, trustPath0.Issuer, StringComparison.Ordinal))
                {
                    // TODO: Improve this error message
                    throw new Fido2VerificationException("Attestation with full attestation from authenticator that does not support full attestation");
                }
            }

            // TODO: Verify all MetadataAttestationTypes are correctly handled

            // [ ] ATTESTATION_ECDAA "ecdaa"    | currently handled as self signed  w/ no test coverage
            // [ ] ATTESTATION_ANONCA "anonca"  | currently not verified            w/ no test coverage
            // [ ] ATTESTATION_NONE "none"      | currently handled as self signed  w/ no test coverage
        }
    }
}
