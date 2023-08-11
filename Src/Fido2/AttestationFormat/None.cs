using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

public sealed class None : AttestationVerifier
{
    public override (AttestationType, X509Certificate2[]) Verify(VerifyAttestationRequest request)
    {
        if (request.AttStmt.Count != 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Attestation format none should have no attestation statement");

        return (AttestationType.None, null!);
    }
}
