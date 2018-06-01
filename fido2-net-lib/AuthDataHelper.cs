using System;
using System.Linq;

namespace fido2NetLib
{
    /// <summary>
    /// Helper functions that implements https://w3c.github.io/webauthn/#authenticator-data
    /// </summary>
    public static class AuthDataHelper
    {
        public static ReadOnlySpan<byte> GetRpIdHash(ReadOnlySpan<byte> authData)
        {
            // todo: Switch to spans
            return authData.Slice(0, 32);
        }

        public static bool IsUserPresent(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x01) != 0;
        }

        public static bool HasExtensions(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x80) != 0;
        }

        public static bool HasAttested(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x40) != 0;
        }

        public static bool IsUserVerified(ReadOnlySpan<byte> authData)
        {
            return (authData[32] & 0x04) != 0;
        }

        public static uint GetSignCount(ReadOnlySpan<byte> ad)
        {
            // https://w3c.github.io/webauthn/#attestedcredentialdata
            return BitConverter.ToUInt32(ad.Slice(32, 4));
        }

        public static (Memory<byte> aaguid, int credIdLen, Memory<byte> credId, Memory<byte> credentialPublicKey) GetAttestionData(Memory<byte> ad)
        {
            int offset = 36; // https://w3c.github.io/webauthn/#attestedcredentialdata
            var aaguid = ad.Slice(offset, 16);
            offset += 16;
            // todo: Do we need to account for little endian?
            int credIdLen;
            if (!BitConverter.IsLittleEndian)
            {
                credIdLen = BitConverter.ToUInt16(ad.Slice(offset, 2).ToArray().Reverse().ToArray());
            }
            else
            {
                credIdLen = BitConverter.ToUInt16(ad.Slice(offset, 2).Span);
            }
            offset += 2;

            var credId = ad.Slice(offset, credIdLen);

            offset += credIdLen;

            var hasExtensions = AuthDataHelper.HasExtensions(ad.Span);

            // Not sure this is working as expected...
            var credentialPublicKey = ad.Slice(offset, (ad.Length - offset)).ToArray();

            // for debugging...
            string hex = BitConverter.ToString(credentialPublicKey);

            var cborcertmap = PeterO.Cbor.CBORObject.DecodeFromBytes(credentialPublicKey);

            return (aaguid, credIdLen, credId, credentialPublicKey);

            // convert to jwk
            // convert to pem


        }
    }
}
