using PeterO.Cbor;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Linq;

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
        internal static byte[] AaguidFromAttnCertExts(X509ExtensionCollection exts)
        {
            byte[] aaguid = null;
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.1.1.4")) // id-fido-gen-ce-aaguid
                {
                    aaguid = new byte[16];
                    var ms = new System.IO.MemoryStream(ext.RawData.ToArray());
                    // OCTET STRING
                    if (0x4 != ms.ReadByte()) throw new Fido2VerificationException("Expected octet string value");
                    // AAGUID
                    if (0x10 != ms.ReadByte()) throw new Fido2VerificationException("Unexpected length for aaguid");
                    ms.Read(aaguid, 0, 0x10);
                    //The extension MUST NOT be marked as critical
                    if (true == ext.Critical) throw new Fido2VerificationException("extension MUST NOT be marked as critical");
                }
            }
            return aaguid;
        }
        internal static bool IsAttnCertCACert(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.FriendlyName == "Basic Constraints")
                {
                    var baseExt = (X509BasicConstraintsExtension)ext;
                    return baseExt.CertificateAuthority;
                }
            }
            return true;
        }
        internal static int U2FTransportsFromAttnCert(X509ExtensionCollection exts)
        {
            var u2ftransports = 0;
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.2.1.1"))
                {
                    var ms = new System.IO.MemoryStream(ext.RawData.ToArray());
                    // BIT STRING
                    if (0x3 != ms.ReadByte()) throw new Fido2VerificationException("Expected bit string");
                    if (0x2 != ms.ReadByte()) throw new Fido2VerificationException("Expected integer value");
                    var unused = ms.ReadByte(); // unused byte
                    // https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-authenticator-transports-extension-v1.1-id-20160915.html#fido-u2f-certificate-transports-extension
                    u2ftransports = ms.ReadByte(); // do something with this?
                }
            }
            return u2ftransports;
        }
        public abstract void Verify();
    }
}
