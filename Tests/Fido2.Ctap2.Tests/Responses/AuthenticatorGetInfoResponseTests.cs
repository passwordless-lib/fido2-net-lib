using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorGetInfoResponseTests
{
    [Fact]
    public void Deserialize()
    {
        string hexEncodedCborData = """

            00                                      # status = success
            ad                                      # map(13)
               01                                   # unsigned(1) - versions
               84                                   # array(4)
                  66                                # text(6)
                     5532465f5632                   # "U2F_V2"
                  68                                # text(8)
                     4649444f5f325f30               # "FIDO_2_0"
                  68                                # text(8)
                     4649444f5f325f31               # "FIDO_2_1"
                  68                                # text(8)
                     4649444f5f325f33               # "FIDO_2_3" - not modelled by this library
               02                                   # unsigned(2) - extensions
               82                                   # array(2)
                  6b                                # text(11)
                     6372656450726f74656374         # "credProtect"
                  6b                                # text(11)
                     686d61632d736563726574         # "hmac-secret"
               03                                   # unsigned(3) - aaguid
               50                                   # bytes(16)
                  fa2b99dc9e3942578f924a30d23c4118  # AAGUID
               04                                   # unsigned(4) - options
               a3                                   # map(3)
                  64                                # text(4)
                     706c6174                       # "plat"
                  f4                                # false
                  62                                # text(2)
                     726b                           # "rk"
                  f5                                # true
                  69                                # text(9)
                     636c69656e7450696e             # "clientPin"
                  f5                                # true
               05                                   # unsigned(5) - maxMsgSize
               19 04b0                              # unsigned(1200)
               06                                   # unsigned(6) - pinProtocols
               82                                   # array(2)
                  01                                # unsigned(1)
                  02                                # unsigned(2)
               18 18                                # unsigned(24) - longTouchForReset
               f5                                   # true
               18 19                                # unsigned(25) - encIdentifier
               58 20                                # bytes(32)
                  000102030405060708090a0b0c0d0e0f  # iv
                  101112131415161718191a1b1c1d1e1f  # ct
               18 1a                                # unsigned(26) - transportsForReset
               82                                   # array(2)
                  63                                # text(3)
                     757362                         # "usb"
                  63                                # text(3)
                     6e6663                         # "nfc"
               18 1b                                # unsigned(27) - pinComplexityPolicy
               f5                                   # true
               18 1d                                # unsigned(29) - maxPINLength
               18 3f                                # unsigned(63)
               18 1e                                # unsigned(30) - encCredStoreState
               44                                   # bytes(4)
                  0a0b0c0d                          # opaque state
               18 7b                                # unsigned(123) - member not modelled by this library
               44                                   # bytes(4)
                  deadbeef                          # opaque
            """;

        var response = AuthenticatorGetInfoResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.Equal(["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_3"], response.Versions!);
        Assert.Equal(["credProtect", "hmac-secret"], response.Extensions!);
        Assert.Equal("fa2b99dc9e3942578f924a30d23c4118", Convert.ToHexString(response.Aaguid!).ToLower());

        Assert.False((bool)response.Options!["plat"]!);
        Assert.True((bool)response.Options["rk"]!);
        Assert.True((bool)response.Options["clientPin"]!);

        Assert.Equal(1200, response.MaxMsgSize);
        Assert.Equal([1, 2], response.PinProtocols!);

        // CTAP 2.2 / 2.3 members
        Assert.True(response.LongTouchForReset);
        Assert.Equal("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", Convert.ToHexString(response.EncIdentifier!).ToLower());
        Assert.Equal(["usb", "nfc"], response.TransportsForReset!);
        Assert.True(response.PinComplexityPolicy);
        Assert.Equal(63, response.MaxPinLength);
        Assert.Equal("0a0b0c0d", Convert.ToHexString(response.EncCredStoreState!).ToLower());
    }

    /// <summary>
    /// An authenticator reporting only the members it knows about must still parse, leaving
    /// everything newer unset rather than failing.
    /// </summary>
    [Fact]
    public void DeserializeLegacyU2fAuthenticator()
    {
        string hexEncodedCborData = """

            00                                      # status = success
            a2                                      # map(2)
               01                                   # unsigned(1) - versions
               81                                   # array(1)
                  66                                # text(6)
                     5532465f5632                   # "U2F_V2"
               03                                   # unsigned(3) - aaguid
               50                                   # bytes(16)
                  00000000000000000000000000000000  # AAGUID
            """;

        var response = AuthenticatorGetInfoResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.Equal(["U2F_V2"], response.Versions!);
        Assert.Equal("00000000000000000000000000000000", Convert.ToHexString(response.Aaguid!).ToLower());

        Assert.Null(response.Extensions);
        Assert.Null(response.Options);
        Assert.Null(response.MaxMsgSize);
        Assert.Null(response.PinProtocols);
        Assert.Null(response.EncIdentifier);
        Assert.Null(response.TransportsForReset);
        Assert.Null(response.EncCredStoreState);
        Assert.Null(response.MaxPinLength);
    }
}
