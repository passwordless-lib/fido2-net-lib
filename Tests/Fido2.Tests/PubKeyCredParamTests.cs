using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Objects;

namespace fido2_net_lib.Test;

public class PubKeyCredParamTests
{
    [Fact]
    public void CanDeserializeES256()
    {
        string json = """{"type":"public-key","alg":-7}""";

        var model = JsonSerializer.Deserialize<PubKeyCredParam>(json);

        Assert.Equal(PublicKeyCredentialType.PublicKey, model.Type);
        Assert.Equal(COSE.Algorithm.ES256, model.Alg);
    }

    [Fact]
    public void CanDeserializeES256K()
    {
        string json = """{"type":"public-key","alg":-47}""";

        var model = JsonSerializer.Deserialize<PubKeyCredParam>(json);

        Assert.Equal(PublicKeyCredentialType.PublicKey, model.Type);
        Assert.Equal(COSE.Algorithm.ES256K, model.Alg);
    }
}
