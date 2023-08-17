using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Exceptions;

namespace Fido2NetLib;

public static class TrustAnchor
{
    public static void Verify(MetadataBLOBPayloadEntry? metadataEntry, X509Certificate2[] trustPath)
    {
        if (trustPath != null && metadataEntry?.MetadataStatement?.AttestationTypes is not null)
        {
            static bool ContainsAttestationType(MetadataBLOBPayloadEntry entry, MetadataAttestationType type)
            {
                return entry.MetadataStatement.AttestationTypes.Contains(type.ToEnumMemberValue());
            }

            // If the authenticator's metadata requires basic full attestation, build and verify the chain
            if (ContainsAttestationType(metadataEntry, MetadataAttestationType.ATTESTATION_BASIC_FULL) ||
                ContainsAttestationType(metadataEntry, MetadataAttestationType.ATTESTATION_PRIVACY_CA))
            {
                string[] certStrings = metadataEntry.MetadataStatement.AttestationRootCertificates;
                var attestationRootCertificates = new X509Certificate2[certStrings.Length];

                for (int i = 0; i < attestationRootCertificates.Length; i++)
                {
                    attestationRootCertificates[i] = new X509Certificate2(Convert.FromBase64String(certStrings[i]));
                }

                if (!CryptoUtils.ValidateTrustChain(trustPath, attestationRootCertificates))
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
