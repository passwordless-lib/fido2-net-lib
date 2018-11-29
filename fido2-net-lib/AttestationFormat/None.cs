using PeterO.Cbor;

namespace Fido2NetLib.AttestationFormat
{
    class None : AttestationFormat
    {
        public None(CBORObject attStmt, byte[] authenticatorData, byte[] clientDataHash) : base(attStmt, authenticatorData, clientDataHash)
        {
        }

        public override void Verify()
        {
            if (0 != attStmt.Keys.Count && 0 != attStmt.Values.Count)
                throw new Fido2VerificationException("Attestation format none should have no attestation statement");
        }
    }
}
