using System;
using System.Linq;
using PeterO.Cbor;

namespace Fido2NetLib
{
    /// <summary>
    /// Helper functions that implements https://w3c.github.io/webauthn/#authenticator-data
    /// </summary>
    public static class AuthDataHelper
    {
        public static byte[] GetSizedByteArray(Memory<byte> ab, ref int offset, ushort len = 0)
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
    // https://www.w3.org/TR/webauthn/#sec-authenticator-data
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
            if (true == ExtensionsPresent) Extensions = AuthDataHelper.GetSizedByteArray(authData, ref offset, (ushort) (authData.Length - offset));
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
    // https://www.w3.org/TR/webauthn/#sec-attested-credential-data
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
            
            CredentialPublicKey = AuthDataHelper.GetSizedByteArray(attData, ref offset, (ushort)(aCDLen));
            if (null == CredentialID || null == CredentialPublicKey) throw new Fido2VerificationException("Attested credential data is invalid");
        }
        public Guid GuidAaguid { get { return FromBigEndian(Aaguid); } }
        public byte[] Aaguid { get; private set; }
        public byte[] CredentialID { get; private set; }
        public byte[] CredentialPublicKey { get; private set; }
    }
}
