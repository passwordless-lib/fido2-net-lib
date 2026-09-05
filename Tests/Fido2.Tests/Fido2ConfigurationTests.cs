using Fido2NetLib;

namespace Test;

public class Fido2ConfigurationTests
{
    [Fact]
    public void GetWellKnownWebAuthn_ReturnsFullyQualifiedConfiguredOrigins()
    {
        var config = new Fido2Configuration
        {
            RPID = "example.com",
            Origins = new HashSet<string> { "https://example.com", "https://sub.example.com" }
        };

        var wellKnown = config.GetWellKnownWebAuthn();

        Assert.Equal(2, wellKnown.Origins.Count);
        Assert.Contains("https://example.com", wellKnown.Origins);
        Assert.Contains("https://sub.example.com", wellKnown.Origins);
    }

    [Fact]
    public void GetWellKnownWebAuthn_PublishesEveryConfiguredOrigin()
    {
        // The five-label figure in the spec is a floor on what clients must process, not a cap on what a
        // Relying Party may publish, and it counts registrable origin labels rather than origins. Truncating
        // here would silently drop origins that clients would otherwise have accepted.
        var origins = Enumerable.Range(0, WellKnownWebAuthn.MinimumClientSupportedLabels + 3)
            .Select(i => $"https://example{i}.com")
            .ToHashSet();

        var config = new Fido2Configuration
        {
            RPID = "example.com",
            Origins = origins
        };

        var wellKnown = config.GetWellKnownWebAuthn();

        Assert.Equal(origins.Count, wellKnown.Origins.Count);
        Assert.All(origins, o => Assert.Contains(o, wellKnown.Origins));
    }

    [Fact]
    public void GetWellKnownWebAuthn_PreservesConfiguredOriginOrder()
    {
        // Clients walk the published list in order and stop taking on new labels at their limit, so the order
        // the Relying Party configured has to survive into the payload.
        string[] origins =
        [
            "https://primary.example.com",
            "https://secondary.example.com",
            "https://tertiary.example.com",
        ];

        var config = new Fido2Configuration
        {
            RPID = "example.com",
            Origins = new LinkedHashSet(origins)
        };

        Assert.Equal(origins, config.GetWellKnownWebAuthn().Origins);
    }

    /// <summary>An <see cref="IReadOnlySet{T}"/> that enumerates in insertion order.</summary>
    private sealed class LinkedHashSet(IEnumerable<string> items) : IReadOnlySet<string>
    {
        private readonly List<string> _ordered = [.. items];
        private readonly HashSet<string> _set = [.. items];

        public int Count => _ordered.Count;
        public IEnumerator<string> GetEnumerator() => _ordered.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        public bool Contains(string item) => _set.Contains(item);
        public bool IsProperSubsetOf(IEnumerable<string> other) => _set.IsProperSubsetOf(other);
        public bool IsProperSupersetOf(IEnumerable<string> other) => _set.IsProperSupersetOf(other);
        public bool IsSubsetOf(IEnumerable<string> other) => _set.IsSubsetOf(other);
        public bool IsSupersetOf(IEnumerable<string> other) => _set.IsSupersetOf(other);
        public bool Overlaps(IEnumerable<string> other) => _set.Overlaps(other);
        public bool SetEquals(IEnumerable<string> other) => _set.SetEquals(other);
    }

    [Fact]
    public void GetWellKnownWebAuthn_ReturnsEmptyWhenNoOriginsConfigured()
    {
        var config = new Fido2Configuration { RPID = "example.com" };

        var wellKnown = config.GetWellKnownWebAuthn();

        Assert.Empty(wellKnown.Origins);
    }

    [Fact]
    public void Validate_AllowsMatchingHttpsOriginAndRPID()
    {
        var config = new Fido2Configuration
        {
            RPID = "example.com",
            Origins = new HashSet<string> { "https://example.com" }
        };

        var exception = Record.Exception(config.Validate);

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_AllowsOriginThatIsRegistrableSubdomainOfRPID()
    {
        var config = new Fido2Configuration
        {
            RPID = "example.com",
            Origins = new HashSet<string> { "https://login.example.com" }
        };

        var exception = Record.Exception(config.Validate);

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_AllowsHttpLoopbackOrigin()
    {
        var config = new Fido2Configuration
        {
            RPID = "localhost",
            Origins = new HashSet<string> { "http://localhost:5000" }
        };

        var exception = Record.Exception(config.Validate);

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_AllowsNonWebOrigins()
    {
        var config = new Fido2Configuration
        {
            RPID = "example.com",
            Origins = new HashSet<string> { "android:apk-key-hash:Ea3dD4m7ccbwcw+a27/D547hfwYra2gKE4lIBbBjCTU" }
        };

        var exception = Record.Exception(config.Validate);

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_SkipsCheckWhenRPIDNotSet()
    {
        var config = new Fido2Configuration
        {
            Origins = new HashSet<string> { "http://unrelated.example.org" }
        };

        var exception = Record.Exception(config.Validate);

        Assert.Null(exception);
    }

    [Fact]
    public void Validate_ThrowsForHttpOriginThatIsNotLoopback()
    {
        var config = new Fido2Configuration
        {
            RPID = "example.com",
            Origins = new HashSet<string> { "http://example.com" }
        };

        Assert.Throws<Fido2ConfigurationException>(config.Validate);
    }

    [Fact]
    public void Validate_ThrowsWhenOriginHostIsNotRelatedToRPID()
    {
        var config = new Fido2Configuration
        {
            RPID = "example.com",
            Origins = new HashSet<string> { "https://not-example.org" }
        };

        Assert.Throws<Fido2ConfigurationException>(config.Validate);
    }

    [Fact]
    public void Validate_ThrowsWhenRPIDIsSubdomainOfOrigin()
    {
        // RPID must be equal to or a registrable suffix *of* the origin's host, not the reverse.
        var config = new Fido2Configuration
        {
            RPID = "login.example.com",
            Origins = new HashSet<string> { "https://example.com" }
        };

        Assert.Throws<Fido2ConfigurationException>(config.Validate);
    }
}
