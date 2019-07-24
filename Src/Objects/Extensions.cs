using System;
using System.Globalization;
using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{
    /// <summary>
    /// <see cref="https://www.w3.org/TR/webauthn/#extensions"/>
    /// </summary>
    public class Extensions
    {
        private readonly byte[] _extensionBytes;
        public Extensions(byte[] extensions)
        {
            _extensionBytes = extensions;
        }
        public override string ToString()
        {
            return string.Format("Extensions: {0}",
                PeterO.Cbor.CBORObject.DecodeFromBytes(_extensionBytes));
        }
        public int Length
        {
            get
            {
                return _extensionBytes.Length;
            }
        }
    }
    public class AuthenticationExtensionsAuthenticatorInputs
    {

    }
}

