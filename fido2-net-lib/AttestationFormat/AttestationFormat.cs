using PeterO.Cbor;
using Fido2NetLib.Objects;
using System;

namespace Fido2NetLib.AttestationFormat
{
    public abstract class AttestationFormat
    {
        public AttestationFormat(CBORObject attStmt, byte[] authenticatorData, byte[] clientDataHash)
        {
            this.attStmt = attStmt;
            this.authenticatorData = authenticatorData;
            this.clientDataHash = clientDataHash;
        }
        public CBORObject attStmt;
        public byte[] authenticatorData;
        public byte[] clientDataHash;
        internal CBORObject Sig { get { return attStmt["sig"]; } }
        internal CBORObject X5c { get { return attStmt["x5c"]; } }
        internal CBORObject Alg { get { return attStmt["alg"]; } }
        internal CBORObject EcdaaKeyId { get { return attStmt["ecdaaKeyId"]; } }
        internal AuthenticatorData AuthData { get { return new AuthenticatorData(authenticatorData); } }
        internal CBORObject CredentialPublicKey { get {return CBORObject.DecodeFromBytes(AuthData.AttData.CredentialPublicKey); } }
        internal byte[] Data
        {
            get
            {
                byte[] data = new byte[authenticatorData.Length + clientDataHash.Length];
                Buffer.BlockCopy(authenticatorData, 0, data, 0, authenticatorData.Length);
                Buffer.BlockCopy(clientDataHash, 0, data, authenticatorData.Length, clientDataHash.Length);
                return data;
            }
        }

        public abstract AttestationFormatVerificationResult Verify();
    }
}
