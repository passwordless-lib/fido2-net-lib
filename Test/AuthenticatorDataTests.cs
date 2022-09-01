using Fido2NetLib;
using Fido2NetLib.Objects;

namespace Test;

public class AuthenticatorDataTests
{
    [Fact]
    public void AuthenticatorDataNull()
    {
        byte[] ad = null;
        var ex = Assert.Throws<Fido2VerificationException>(() => new AuthenticatorData(ad));
        Assert.Equal("Authenticator data cannot be null", ex.Message);
    }

    [Fact]
    public void AuthenticatorDataMinLen()
    {
        byte[] ad = new byte[36];
        var ex = Assert.Throws<Fido2VerificationException>(() => new AuthenticatorData(ad));
        Assert.Equal("Authenticator data is less than the minimum structure length of 37", ex.Message);
    }

    [Fact]
    public void AuthenticatorDataExtraBytes()
    {
        byte[] ad = Convert.FromHexString("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000000000000000000000000000000000000000040ee726cb6daf874b4ac9ab5a76870777aca49d2e6bdaec276c2cfbddc115c34e3fae20fecff8c0b143be496b358720d0108de9d7548c92f10df0d206b78a40b03a501020326200121582050e028e71aac2683df256b14e7487b7364bbfe594fd0ac0623abc99048f5378f225820364cc49e05f849f381f23104208c9bc1880e899c7034721c52966b99793f578242");
        var ex = Assert.Throws<Fido2VerificationException>(() => new AuthenticatorData(ad));
        Assert.Equal("Leftover bytes decoding AuthenticatorData", ex.Message);
    }
}
