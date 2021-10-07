using System.Security.Cryptography.X509Certificates;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{
    public sealed class None : AttestationVerifier
    {
        public override (AttestationType, X509Certificate2[]) Verify()
        {
            if (0 != attStmt.Keys.Count && 0 != attStmt.Values.Count)
                throw new Fido2VerificationException("Attestation format none should have no attestation statement");

            return (AttestationType.None, null);
        }
    }
}
