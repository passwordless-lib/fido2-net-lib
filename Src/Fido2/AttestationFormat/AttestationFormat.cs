using PeterO.Cbor;
using System;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib.Objects;
using Asn1;
using System.Linq;

namespace Fido2NetLib
{
    public abstract class AttestationVerifier
    {
        public CBORObject attStmt;
        public byte[] authenticatorData;
        public byte[] clientDataHash;

        internal CBORObject Sig => attStmt["sig"];
        internal CBORObject X5c => attStmt["x5c"];
        internal CBORObject Alg => attStmt["alg"];
        internal CBORObject EcdaaKeyId => attStmt["ecdaaKeyId"];
        internal AuthenticatorData AuthData => new AuthenticatorData(authenticatorData);
        internal CBORObject CredentialPublicKey => AuthData.AttestedCredentialData.CredentialPublicKey.GetCBORObject();
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
        internal static byte[] AaguidFromAttnCertExts(X509ExtensionCollection exts)
        {
            byte[] aaguid = null;
            var ext = exts.Cast<X509Extension>().FirstOrDefault(e => e.Oid.Value == "1.3.6.1.4.1.45724.1.1.4"); // id-fido-gen-ce-aaguid
            if (null != ext)
            {
                var decodedAaguid = AsnElt.Decode(ext.RawData);
                decodedAaguid.CheckTag(AsnElt.OCTET_STRING);
                decodedAaguid.CheckPrimitive();
                aaguid = decodedAaguid.GetOctetString();

                //The extension MUST NOT be marked as critical
                if (true == ext.Critical)
                    throw new Fido2VerificationException("extension MUST NOT be marked as critical");
            }

            return aaguid;
        }
        internal static bool IsAttnCertCACert(X509ExtensionCollection exts)
        {
            var ext = exts.Cast<X509Extension>().FirstOrDefault(e => e.Oid.Value == "2.5.29.19");
            if (null != ext && ext is X509BasicConstraintsExtension baseExt)
            {
                return baseExt.CertificateAuthority;
            }

            return true;
        }
        internal static byte U2FTransportsFromAttnCert(X509ExtensionCollection exts)
        {
            var u2ftransports = new byte();
            var ext = exts.Cast<X509Extension>().FirstOrDefault(e => e.Oid.Value == "1.3.6.1.4.1.45724.2.1.1");
            if (null != ext)
            {
                var decodedU2Ftransports = AsnElt.Decode(ext.RawData);
                decodedU2Ftransports.CheckPrimitive();

                // some certificates seem to have this encoded as an octet string
                // instead of a bit string, attempt to correct
                if (AsnElt.OCTET_STRING == decodedU2Ftransports.TagValue)
                {
                    ext.RawData[0] = AsnElt.BIT_STRING;
                    decodedU2Ftransports = AsnElt.Decode(ext.RawData);
                }
                decodedU2Ftransports.CheckTag(AsnElt.BIT_STRING);
                u2ftransports = decodedU2Ftransports.GetBitString()[0];
            }

            return u2ftransports;
        }
        public virtual (AttestationType, X509Certificate2[]) Verify(CBORObject attStmt, byte[] authenticatorData, byte[] clientDataHash)
        {
            this.attStmt = attStmt;
            this.authenticatorData = authenticatorData;
            this.clientDataHash = clientDataHash;
            return Verify();
        }

        public abstract (AttestationType, X509Certificate2[]) Verify();
    }
}
