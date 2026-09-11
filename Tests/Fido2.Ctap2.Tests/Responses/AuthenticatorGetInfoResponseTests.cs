using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

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
    /// Covers the members neither <see cref="Deserialize"/> nor <see cref="DeserializeLegacyU2fAuthenticator"/>
    /// touch: 0x07 through 0x17, plus 0x1C and 0x1F. Generated with Python's cbor2 (canonical=False) rather
    /// than hand-encoded, since this is a map(19).
    /// </summary>
    [Fact]
    public void DeserializeRemainingCtap22And23Members()
    {
        string hexEncodedCborData = """

            00                                      # status = success
            b3                                      # map(19)
            07 0a                                   # 0x07 maxCredentialCountInList = 10
            08 1880                                 # 0x08 maxCredentialIdLength = 128
            09 8263757362636e6663                   # 0x09 transports = ["usb", "nfc"]
            0a 81a163616c6726                        # 0x0A algorithms = [{"alg": -7}]
            0b 190400                               # 0x0B maxSerializedLargeBlobArray = 1024
            0c f5                                   # 0x0C forcePINChange = true
            0d 04                                   # 0x0D minPINLength = 4
            0e 1a00050506                           # 0x0E firmwareVersion = 328966
            0f 1820                                 # 0x0F maxCredBlobLength = 32
            10 01                                   # 0x10 maxRPIDsForSetMinPINLength = 1
            11 03                                   # 0x11 preferredPlatformUvAttempts = 3
            12 02                                   # 0x12 uvModality = 2
            13 a16c464950532d434d56502d4c3101       # 0x13 certifications = {"FIPS-CMVP-L1": 1}
            14 1832                                 # 0x14 remainingDiscoverableCredentials = 50
            15 820102                               # 0x15 vendorPrototypeConfigCommands = [1, 2]
            16 82667061636b6564646e6f6e65            # 0x16 attestationFormats = ["packed", "none"]
            17 02                                   # 0x17 uvCountSinceLastPinEntry = 2
            181c 44aabbccdd                         # 0x1C pinComplexityPolicyURL = 0xaabbccdd
            181f 83010203                           # 0x1F authenticatorConfigCommands = [1, 2, 3]
            """;

        var response = AuthenticatorGetInfoResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.Equal(10, response.MaxCredentialCountInList);
        Assert.Equal(128, response.MaxCredentialIdLength);
        Assert.Equal(["usb", "nfc"], response.Transports!);
        Assert.Single(response.Algorithms!);
        Assert.Equal(COSE.Algorithm.ES256, response.Algorithms![0].Alg);
        Assert.Equal(1024, response.MaxSerializedLargeBlobArray);
        Assert.True(response.ForcePinChange);
        Assert.Equal(4, response.MinPinLength);
        Assert.Equal(328966, response.FirmwareVersion);
        Assert.Equal(32, response.MaxCredBlobLength);
        Assert.Equal(1, response.MaxRpidsForSetMinPinLength);
        Assert.Equal(3, response.PreferredPlatformUvAttempts);
        Assert.Equal(2, response.UvModality);
        Assert.Equal(1, (int)response.Certifications!["FIPS-CMVP-L1"]!);
        Assert.Equal(50, response.RemainingDiscoverableCredentials);
        Assert.Equal([1, 2], response.VendorPrototypeConfigCommands!);
        Assert.Equal(["packed", "none"], response.AttestationFormats!);
        Assert.Equal(2, response.UvCountSinceLastPinEntry);
        Assert.Equal("aabbccdd", Convert.ToHexString(response.PinComplexityPolicyUrl!).ToLower());
        Assert.Equal([1, 2, 3], response.AuthenticatorConfigCommands!);
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
