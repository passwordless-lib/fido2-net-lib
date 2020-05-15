using System;
using System.Collections.Generic;
using System.Text;
using fido2_net_lib.Test;
using PeterO.Cbor;

namespace Test.Attestation
{
    class AndroidSafetyNet : Fido2Tests.Attestation
    {
        public AndroidSafetyNet()
        {
            _attestationObject = CBORObject.NewMap().Add("fmt", "android-safetynet");
        }
    }
}
