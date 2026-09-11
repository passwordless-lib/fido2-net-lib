using Fido2NetLib;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// <see cref="Fido2.RequestNewCredential"/> (and the <see cref="CredentialCreateOptions.Create"/> factory it
/// calls) had no test coverage at all before these -- every other test in this suite exercises registration
/// verification by constructing <see cref="CredentialCreateOptions"/> directly, never through this options-
/// generation path.
/// </summary>
public class RequestNewCredentialTests
{
    private static Fido2 MakeLib() => new(new Fido2Configuration
    {
        RPID = "example.org",
        RPName = "example.org",
        Origins = new HashSet<string> { "https://example.org" },
    });

    [Fact]
    public void RequestNewCredential_WithValidUserHandle_ReturnsOptions()
    {
        var lib = MakeLib();
        var user = new Fido2User
        {
            Id = [0xf1, 0xd0],
            Name = "testuser",
            DisplayName = "Test User",
        };

        var options = lib.RequestNewCredential(new RequestNewCredentialParams { User = user });

        Assert.Same(user, options.User);
        Assert.Equal("example.org", options.Rp.Id);
        Assert.NotEmpty(options.Challenge);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(64)]
    public void RequestNewCredential_WithBoundaryUserHandleLength_Succeeds(int length)
    {
        var lib = MakeLib();
        var user = new Fido2User
        {
            Id = new byte[length],
            Name = "testuser",
            DisplayName = "Test User",
        };

        var options = lib.RequestNewCredential(new RequestNewCredentialParams { User = user });

        Assert.Equal(length, options.User.Id.Length);
    }

    [Fact]
    public void RequestNewCredential_WithEmptyUserHandle_ThrowsArgumentException()
    {
        var lib = MakeLib();
        var user = new Fido2User
        {
            Id = [],
            Name = "testuser",
            DisplayName = "Test User",
        };

        var ex = Assert.Throws<ArgumentException>(() => lib.RequestNewCredential(new RequestNewCredentialParams { User = user }));
        Assert.Equal("user", ex.ParamName);
    }

    [Fact]
    public void RequestNewCredential_WithNullUserHandle_ThrowsArgumentException()
    {
        var lib = MakeLib();
        var user = new Fido2User
        {
            Id = null,
            Name = "testuser",
            DisplayName = "Test User",
        };

        var ex = Assert.Throws<ArgumentException>(() => lib.RequestNewCredential(new RequestNewCredentialParams { User = user }));
        Assert.Equal("user", ex.ParamName);
    }

    [Fact]
    public void RequestNewCredential_WithOversizedUserHandle_ThrowsArgumentException()
    {
        var lib = MakeLib();
        var user = new Fido2User
        {
            Id = new byte[65],
            Name = "testuser",
            DisplayName = "Test User",
        };

        var ex = Assert.Throws<ArgumentException>(() => lib.RequestNewCredential(new RequestNewCredentialParams { User = user }));
        Assert.Equal("user", ex.ParamName);
    }
}
