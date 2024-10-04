using System.Text.Json;

namespace Fido2NetLib.Objects.Tests;

public class AttestationTypeTests
{
    [Fact]
    public void ImplicitlyConvertibleToString()
    {
        Assert.Equal("none", AttestationType.None);
    }

    [Fact]
    public void CanSerialize()
    {
        Assert.Equal("\"none\"", JsonSerializer.Serialize(AttestationType.None));
        Assert.Equal("\"ecdaa\"", JsonSerializer.Serialize(AttestationType.ECDAA));
    }

    [Fact]
    public void CanDeserialize()
    {
        Assert.Same(AttestationType.None, JsonSerializer.Deserialize<AttestationType>("\"none\""));
        Assert.Same(AttestationType.ECDAA, JsonSerializer.Deserialize<AttestationType>("\"ecdaa\""));
    }
}
