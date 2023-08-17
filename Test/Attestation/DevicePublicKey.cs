using System.Text.Json;
using fido2_net_lib.Test;

using Fido2NetLib.Objects;

namespace Test.Attestation;

public class DevicePublicKey : Fido2Tests.Attestation
{
    [Fact]
    public void TestDevicePublicKey()
    {
        string json = """{"authenticatorOutput":"pmNkcGtYTaUBAgMmIAEhWCBNwZidDC8QQNAffsFaxUKxTbVLxepdV-1_azg-u0-rsCJYIFtht9l1L8g2hqQOo8omnBd9fRj2byJzn1JQqnp19oVbY2ZtdGRub25lZW5vbmNlQGVzY29wZQBmYWFndWlkUAAAAAAAAAAAAAAAAAAAAABnYXR0U3RtdKA=","signature":"MEUCIQDTf2ImngEOi3qHws6gxf6CpquI97oDIl8m_4T2xQO-YwIgdWN7elqNuU-yMZtGpy8hQtL_E-qmZ1_rM2u2nhXYw7A="}""";

        var model = JsonSerializer.Deserialize<AuthenticationExtensionsDevicePublicKeyOutputs>(json);
        var devicePublicKeyAuthenticatorOutput = DevicePublicKeyAuthenticatorOutput.Parse(model.AuthenticatorOutput);
        Assert.Equal("none", devicePublicKeyAuthenticatorOutput.Fmt);
    }
}
