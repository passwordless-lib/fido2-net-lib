using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PeterO.Cbor;

namespace Fido2NetLib
{
    /// <summary>
    /// Helper functions that implements https://w3c.github.io/webauthn/#authenticator-data
    /// </summary>
    public static class AuthDataHelper
    {
        public static byte[] AaguidFromAttnCertExts(X509ExtensionCollection exts)
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
        public static string SANFromAttnCertExts(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.17")) // subject alternative name
                {
                    var asn = new AsnEncodedData(ext.Oid, ext.RawData);
                    return asn.Format(true);
                }
            }
            return null;
        }
        public static string EKUFromAttnCertExts(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.37")) // EKU
                {
                    var asn = new AsnEncodedData(ext.Oid, ext.RawData);
                    return asn.Format(false);
                }
            }
            return null;
        }
        public static bool IsAttnCertCACert(X509ExtensionCollection exts)
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
        public static byte[] AttestationExtensionBytes(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.11129.2.1.17")) // AttestationRecordOid
                {
                    return ext.RawData;
                }
            }
            return null;
        }

        public static int U2FTransportsFromAttnCert(X509ExtensionCollection exts)
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

        public static bool IsValidPackedAttnCertSubject(string attnCertSubj)
        {
            var dictSubject = attnCertSubj.Split(new string[] { ", " }, StringSplitOptions.None).Select(part => part.Split('=')).ToDictionary(split => split[0], split => split[1]);
            return (0 != dictSubject["C"].Length ||
                0 != dictSubject["O"].Length ||
                0 != dictSubject["OU"].Length ||
                0 != dictSubject["CN"].Length ||
                "Authenticator Attestation" == dictSubject["OU"].ToString());
        }

        public static byte[] GetSizedByteArray(Memory<byte> ab, ref int offset, UInt16 len = 0)
        {
            if ((0 == len) && ((offset + 2) <= ab.Length))
            {
                len = BitConverter.ToUInt16(ab.Slice(offset, 2).ToArray().Reverse().ToArray(), 0);
                offset += 2;
            }
            byte[] result = null;
            if ((0 < len) && ((offset + len) <= ab.Length)) 
            {
                result = ab.Slice(offset, len).ToArray();
                offset += len;
            }
            return result;
        }
    }
        // https://w3c.github.io/webauthn/#authenticator-data
    public class AuthenticatorData
    {
        enum authDataFlags
        {
            UP,
            RFU1,
            UV,
            RFU2,
            RFU3,
            RFU4,
            AT,
            ED
        }
        public AuthenticatorData(byte[] authData)
        {
            if (null == authData || authData.Length < 37) throw new Fido2VerificationException("Authenticator data is invalid");
            var offset = 0;
            RpIdHash = AuthDataHelper.GetSizedByteArray(authData, ref offset, 32);
            Flags = AuthDataHelper.GetSizedByteArray(authData, ref offset, 1)[0];
            SignCount = AuthDataHelper.GetSizedByteArray(authData, ref offset, 4);
            if (false == AttestedCredentialDataPresent && false == ExtensionsPresent && 37 != authData.Length) throw new Fido2VerificationException("Authenticator data flags and data mismatch");
            AttData = null;
            Extensions = null;
            // Determining attested credential data's length, which is variable, involves determining credentialPublicKey’s beginning location given the preceding credentialId’s length, and then determining the credentialPublicKey’s length
            if (true == AttestedCredentialDataPresent) AttData = new AttestedCredentialData(authData, ref offset);
            if (true == ExtensionsPresent) Extensions = AuthDataHelper.GetSizedByteArray(authData, ref offset, (UInt16) (authData.Length - offset));
            if (authData.Length != offset) throw new Fido2VerificationException("Leftover bytes decoding AuthenticatorData");
        }
        public byte[] RpIdHash { get; private set; }
        public byte Flags { get; private set; }
        public byte[] SignCount { get; private set; }
        public AttestedCredentialData AttData { get; private set; }
        public byte[] Extensions { get; private set; }
        public bool UserPresent { get { return ((Flags & (1 << (int) authDataFlags.UP)) != 0); } }
        public bool Reserved1 { get { return ((Flags & (1 << (int) authDataFlags.RFU1)) != 0); } }
        public bool UserVerified { get { return ((Flags & (1 << (int) authDataFlags.UV)) != 0); } }
        public bool Reserved2 { get { return ((Flags & (1 << (int) authDataFlags.RFU2)) != 0); } }
        public bool Reserved3 { get { return ((Flags & (1 << (int) authDataFlags.RFU3)) != 0); } }
        public bool Reserved4 { get { return ((Flags & (1 << (int) authDataFlags.RFU4)) != 0); } }
        public bool AttestedCredentialDataPresent { get { return ((Flags & (1 << (int) authDataFlags.AT)) != 0); } }
        public bool ExtensionsPresent { get { return ((Flags & (1 << (int) authDataFlags.ED)) != 0); } }
    }
    // https://w3c.github.io/webauthn/#attested-credential-data
    public class AttestedCredentialData
    {
        public static Guid FromBigEndian(byte[] Aaguid)
        {
            byte[] guid = new byte[16];
            for (int i = 8; i < 16; i++)
            {
                guid[i] = Aaguid[i];
            }
            guid[3] = Aaguid[0];
            guid[2] = Aaguid[1];
            guid[1] = Aaguid[2];
            guid[0] = Aaguid[3];
            guid[5] = Aaguid[4];
            guid[4] = Aaguid[5];
            guid[6] = Aaguid[7];
            guid[7] = Aaguid[6];
            return new Guid(guid);
        }
        public AttestedCredentialData(byte[] attData, ref int offset)
        {
            Aaguid = AuthDataHelper.GetSizedByteArray(attData, ref offset, 16);
            if (null == Aaguid) throw new Fido2VerificationException("Attested credential data is invalid");
            GuidAaguid = FromBigEndian(Aaguid);
            CredentialID = AuthDataHelper.GetSizedByteArray(attData, ref offset);
            // Determining attested credential data's length, which is variable, involves determining credentialPublicKey’s beginning location given the preceding credentialId’s length, and then determining the credentialPublicKey’s length
            var ms = new System.IO.MemoryStream(attData, offset, attData.Length - offset);
            // CBORObject.Read: This method will read from the stream until the end of the CBOR object is reached or an error occurs, whichever happens first.
            CBORObject tmp = null;
            try
            {
                tmp = CBORObject.Read(ms);
            }
            catch (Exception)
            {
                throw new Fido2VerificationException("Failed to read credential public key from attested credential data");
            }
            var aCDLen = tmp.EncodeToBytes().Length;
            
            CredentialPublicKey = AuthDataHelper.GetSizedByteArray(attData, ref offset, (UInt16)(aCDLen));
            if (null == CredentialID || null == CredentialPublicKey) throw new Fido2VerificationException("Attested credential data is invalid");
        }
        public Guid GuidAaguid { get; private set; }
        public byte[] Aaguid { get; private set; }
        public byte[] CredentialID { get; private set; }
        public byte[] CredentialPublicKey { get; private set; }
    }
}
