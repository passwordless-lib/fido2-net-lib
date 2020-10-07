using fido2_net_lib.Test;
using PeterO.Cbor;

namespace Test.Attestation
{
    public class Apple : Fido2Tests.Attestation
    {
        public Apple()
        {
            _attestationObject = CBORObject.NewMap().Add("fmt", "apple");
        }
    }
}
