namespace Fido2NetLib.Cbor.Tests;

public class CborTests
{
    [Fact]
    public void CanRoundtripAttestationObject()
    {
        byte[] data = Convert.FromBase64String("o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmN4NWOBWQI4MIICNDCCAdqgAwIBAgIIbP/m0XJp+h0wCgYIKoZIzj0EAwIwZTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8yLU5FVC1MSUIxIjAgBgNVBAsTGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMTEUFuZHJvaWRLZXlUZXN0aW5nMB4XDTIxMTAyMTIxMjQyOVoXDTIxMTAyMzIxMjQyOVowZTELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8yLU5FVC1MSUIxIjAgBgNVBAsTGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMTEUFuZHJvaWRLZXlUZXN0aW5nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErD2wtqLp3HpUsGm+08B6OuHU0g1/mfFBQp17sNcT58UEP5hRcLA6gBzYTTSKJguHHObIZKaznpgmhGuoJktQJqN0MHIwcAYKKwYBBAHWeQIBEQRiMGACAQMgAwQBAAIBAiADBAEABCABfDdfwPehWBVL2KIcBZflxAraVzzPoB2bIb9ZUqt97gQQdtUq+XMm5XeYF19E1SnYXDAKv4U9BgIEYXHajTAOoQUxAwIBAr+FPgMCAQAwCgYIKoZIzj0EAwIDSAAwRQIhAO2qKj24OmDeoraK6uQxASCTC6OFkwCX8D9HJFCuWCakAiBIsi0iTFpLWh/Q7Kh1tAtaFTLTLuxGxbd+OTm84pCzAGNzaWdYRjBEAiAeGtIfwX9z0Pxnmm4oYJtRp5RNWoxiHA79k3BabqPiWAIgCSmuGYXZUdXIcI5nc7KQfUxsrx6V9Mw+ArI3zaHj+vloYXV0aERhdGFYnv9czfK4WoSxjg1ak+qI4nnuPi5B6vqMNNQfxy6+8nRAxQAAhVLx0PHQ8dDx0PHQ8dDx0PHQABB21Sr5cybld5gXX0TVKdhcpQECAyYhWCCsPbC2ouncelSwab7TwHo64dTSDX+Z8UFCnXuw1xPnxSJYIAQ/mFFwsDqAHNhNNIomC4cc5shkprOemCaEa6gmS1AmIAGhZ3Rlc3Rpbmf1");

        var @object = (CborMap)CborObject.Decode(data);

        Assert.Equal("android-key", ((CborTextString)@object["fmt"]).Value);
        Assert.Equal(158,           ((CborByteString)@object["authData"]).Value.Length);

        var attStmt = (CborMap)@object["attStmt"];

        Assert.Equal(-7,  ((CborInteger)attStmt["alg"]).Value);
        Assert.Equal(1,   ((CborArray)attStmt["x5c"]).Length);
        Assert.Equal(70,  ((CborByteString)attStmt["sig"]).Value.Length);

        Assert.Equal(data, @object.Encode());
    }

    [Fact]
    public void CanReadObjectAndIgnoreRemainingData()
    {
        byte[] data = Convert.FromBase64String("pQECAzguIVggy6rAanAqDpv7VJqZVJWgUVG6jIQvURLOH9Ylf/+nyesiWCDb75V3vgcbm7P0M1pI55cc6EkopDxVV7RXKQfm/xNlNyAIoWd0ZXN0aW5n9Q==");

        var map = (CborMap)CborObject.Decode(data, out int read);

        Assert.Equal(88, data.Length);
        Assert.Equal(78, read);

        var keys = map.Keys.Select(k => ((CborInteger)k).Value);

        Assert.Equal(2,    ((CborInteger)map[new CborInteger(1)]).Value);
        Assert.Equal(-47,  ((CborInteger)map[new CborInteger(3)]).Value);
        Assert.Equal("y6rAanAqDpv7VJqZVJWgUVG6jIQvURLOH9Ylf/+nyes=", Convert.ToBase64String(((CborByteString)map[new CborInteger(-2)]).Value));
        Assert.Equal("2++Vd74HG5uz9DNaSOeXHOhJKKQ8VVe0VykH5v8TZTc=", Convert.ToBase64String(((CborByteString)map[new CborInteger(-3)]).Value));
        Assert.Equal(8,    ((CborInteger)map[new CborInteger(-1)]).Value);

        // Ensure we ignored the remaining data

        var encoded = map.Encode();

        Assert.Equal("pQECAzguIVggy6rAanAqDpv7VJqZVJWgUVG6jIQvURLOH9Ylf/+nyesiWCDb75V3vgcbm7P0M1pI55cc6EkopDxVV7RXKQfm/xNlNyAI", Convert.ToBase64String(encoded));

        Assert.Equal(78, encoded.Length);
    }
}
