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

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(Fido2.MinimumChallengeSize - 1)]
    public void ChallengesShorterThanTheMinimumAreRefused(int challengeSize)
    {
        // A challenge of 0 bytes used to be issued as configured, and then matched any response with an empty one.
        var lib = new Fido2(new Fido2Configuration
        {
            RPID = "example.org",
            RPName = "example.org",
            Origins = new HashSet<string> { "https://example.org" },
            ChallengeSize = challengeSize,
        });
        var user = new Fido2User { Id = [0xf1, 0xd0], Name = "testuser", DisplayName = "Test User" };

        Assert.Throws<Fido2ConfigurationException>(() => lib.RequestNewCredential(new RequestNewCredentialParams { User = user }));
        Assert.Throws<Fido2ConfigurationException>(() => lib.GetAssertionOptions(new GetAssertionOptionsParams()));
        Assert.Throws<Fido2ConfigurationException>(() => lib.GetAssertionOptions([], null));
    }

    [Fact]
    public void ChallengesOfTheMinimumSizeAreIssued()
    {
        var lib = new Fido2(new Fido2Configuration
        {
            RPID = "example.org",
            RPName = "example.org",
            Origins = new HashSet<string> { "https://example.org" },
            ChallengeSize = Fido2.MinimumChallengeSize,
        });
        var user = new Fido2User { Id = [0xf1, 0xd0], Name = "testuser", DisplayName = "Test User" };

        Assert.Equal(Fido2.MinimumChallengeSize, lib.RequestNewCredential(new RequestNewCredentialParams { User = user }).Challenge.Length);
        Assert.Equal(Fido2.MinimumChallengeSize, lib.GetAssertionOptions(new GetAssertionOptionsParams()).Challenge.Length);
        Assert.Equal(Fido2.MinimumChallengeSize, lib.GetAssertionOptions([], null).Challenge.Length);
    }

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
