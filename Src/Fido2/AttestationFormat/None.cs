using System.Threading.Tasks;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

public sealed class None : AttestationVerifier
{
    public override ValueTask<VerifyAttestationResult> VerifyAsync(VerifyAttestationRequest request)
    {
        if (request.AttStmt.Count != 0)
            throw new Fido2VerificationException(Fido2ErrorCode.InvalidAttestation, "Attestation format none should have no attestation statement");

        return new(new VerifyAttestationResult(AttestationType.None, null!));
    }
}
