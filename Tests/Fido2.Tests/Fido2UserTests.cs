using System.Text.Json;

namespace Fido2NetLib.Tests;

public class Base64UrlConverterTests
{
    [Fact]
    public void RelaxedDecodingWorks()
    {
        string jsonText =
            """
            {
              "name": "anders",
              "id": "7w80qsdaWWm5R+KK2O64MO/WSitunFbxH1H8mE9IVORxzbXdxXDY1VRQlayoK/Lmh3MI/p0M59Rh98D8r4EoJw==",
              "displayName": "anders"
            }
            """;

        Base64UrlConverter.EnableRelaxedDecoding = false;

        try
        {
            _ = JsonSerializer.Deserialize<Fido2User>(jsonText);
        }
        catch (JsonException ex)
        {
            Assert.Equal("Expected data to be in Base64Url format, but received Base64 encoding instead.", ex.Message);
        }

        Base64UrlConverter.EnableRelaxedDecoding = true;

        var user = JsonSerializer.Deserialize<Fido2User>(jsonText);

        Assert.Equal("7w80qsdaWWm5R+KK2O64MO/WSitunFbxH1H8mE9IVORxzbXdxXDY1VRQlayoK/Lmh3MI/p0M59Rh98D8r4EoJw==", Convert.ToBase64String(user.Id));
    }
}
