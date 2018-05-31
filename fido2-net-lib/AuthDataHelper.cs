using System.Linq;

namespace fido2NetLib
{
    /// <summary>
    /// Helper functions that implements https://w3c.github.io/webauthn/#authenticator-data
    /// </summary>
    public static class AuthDataHelper
    {
        public static byte[] GetRpIdHash(byte[] authData)
        {
            // todo: Switch to spans
            return authData.Take(32).ToArray();
        }

        public static bool IsUserPresent(byte[] authData)
        {
            var flagByte = authData[32];
            int userPresentPos = 0;
            return (flagByte & (1 << userPresentPos)) != 0;
        }
    }
}
