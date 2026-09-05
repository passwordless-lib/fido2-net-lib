#nullable disable

using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

public class Fido2Configuration
{
    private IReadOnlySet<string> _origins;
    private IReadOnlySet<string> _fullyQualifiedOrigins;

    /// <summary>
    /// Create the configuration for Fido2.
    /// </summary>
    public Fido2Configuration()
    {
    }

    /// <summary>
    /// This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
    /// This is treated as a hint, and MAY be overridden by the client.
    /// </summary>
    public uint Timeout { get; set; } = 60000;

    /// <summary>
    /// TimestampDriftTolerance specifies a time in milliseconds that will be allowed for clock drift on a timestamped attestation.
    /// </summary>
    public int TimestampDriftTolerance { get; set; } = 0; //Pretty sure 0 will never work - need a better default?

    /// <summary>
    /// The size of the challenges sent to the client
    /// </summary>
    public int ChallengeSize { get; set; } = 16;

    /// <summary>
    /// The effective domain of the RP. Should be unique and will be used as the identity for the RP.
    /// </summary>
    public string RPID { get; set; }

    /// <summary>
    /// A human-friendly name of the RP.
    /// </summary>
    public string RPName { get; set; }

    /// <inheritdoc cref="RPID"/>
    [Obsolete("Use RPID instead. This property will be removed in a future major version.")]
    public string ServerDomain
    {
        get => RPID;
        set => RPID = value;
    }

    /// <inheritdoc cref="RPName"/>
    [Obsolete("Use RPName instead. This property will be removed in a future major version.")]
    public string ServerName
    {
        get => RPName;
        set => RPName = value;
    }

    /// <summary>
    /// A serialized URL which resolves to an image associated with the entity. For example, this could be a user’s avatar or a Relying Party's logo. This URL MUST be an a priori authenticated URL. Authenticators MUST accept and store a 128-byte minimum length for an icon member’s value. Authenticators MAY ignore an icon member’s value if its length is greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches of the URL, at the cost of needing more storage.
    /// </summary>
    public string ServerIcon { get; set; }

    /// <summary>
    /// Server origins, including protocol host and port.
    /// </summary>
    public IReadOnlySet<string> Origins
    {
        get
        {
            _origins ??= new HashSet<string>(0);

            return _origins;
        }

        set
        {
            _origins = value;
            _fullyQualifiedOrigins = new HashSet<string>(value.Select(o => o.ToFullyQualifiedOrigin()), StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Fully Qualified Server origins, generated automatically from Origins.
    /// </summary>
    public IReadOnlySet<string> FullyQualifiedOrigins
    {
        get
        {
            if (_fullyQualifiedOrigins == null)
            {
                Origins = new HashSet<string>(0);
            }

            return _fullyQualifiedOrigins;
        }
    }

    /// <summary>
    /// Builds the payload to serve from this RP ID's <c>/.well-known/webauthn</c> endpoint, listing every
    /// configured origin so user agents can validate
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">related origin requests</see>.
    /// </summary>
    /// <remarks>
    /// The spec places no limit on how many origins a Relying Party publishes. Clients are only required to
    /// process <see cref="WellKnownWebAuthn.MinimumClientSupportedLabels"/> distinct <i>registrable origin
    /// labels</i>, walking the list in order, so <see cref="Origins"/> should be ordered with the most important
    /// labels first. Note that many origins can share one label -- see
    /// <see cref="WellKnownWebAuthn.MinimumClientSupportedLabels"/>.
    /// </remarks>
    public WellKnownWebAuthn GetWellKnownWebAuthn()
    {
        // Project from Origins rather than FullyQualifiedOrigins so the caller's enumeration order survives:
        // clients walk the published list in order and stop taking on new labels once they hit their limit.
        return new WellKnownWebAuthn
        {
            Origins = [.. Origins.Select(o => o.ToFullyQualifiedOrigin()).Distinct(StringComparer.OrdinalIgnoreCase)]
        };
    }

    /// <summary>
    /// Verifies that every configured <see cref="Origins"/> entry is a scheme/RP ID pair the
    /// WebAuthn registration/authentication ceremonies can legitimately accept: the origin's
    /// scheme must be <c>https</c> (or the origin must be loopback, for local development), and
    /// <see cref="RPID"/> must equal the origin's host or be a registrable domain suffix of it.
    /// </summary>
    /// <remarks>
    /// This is an opt-in, defense-in-depth sanity check on configuration -- it is not called
    /// automatically, and is not a substitute for the per-ceremony origin comparison performed in
    /// <c>AuthenticatorResponse.BaseVerify</c>, which remains the actual security boundary.
    /// Call it once at application startup (e.g. immediately after building a
    /// <see cref="Fido2Configuration"/>, or via <c>IValidateOptions&lt;Fido2Configuration&gt;</c>
    /// / <c>ValidateOnStart()</c> in ASP.NET Core) to fail fast on a misconfigured
    /// <see cref="Origins"/>/<see cref="RPID"/> pair, per WebAuthn L3 §13.4.9.
    /// </remarks>
    /// <exception cref="Fido2ConfigurationException">
    /// Thrown when <see cref="RPID"/> is set and a configured origin doesn't satisfy the above.
    /// </exception>
    public void Validate()
    {
        if (string.IsNullOrEmpty(RPID))
            return;

        // RPID should be a bare domain per spec, but this library has historically tolerated a
        // full origin URL here too (the value is otherwise only ever hashed/compared verbatim
        // against itself). Accept either form by comparing against the effective host.
        var rpIdHost = Uri.TryCreate(RPID, UriKind.Absolute, out var rpIdUri) ? rpIdUri.Host : RPID;

        foreach (var origin in Origins)
        {
            Uri uri;
            try
            {
                uri = new Uri(origin);
            }
            catch (UriFormatException e)
            {
                throw new Fido2ConfigurationException($"Configured origin '{origin}' is not a valid URI", e);
            }

            // Only web origins have a meaningful host/registrable-domain relationship to an RP ID.
            // Non-web schemes (e.g. "android:apk-key-hash:...", used for native app callers) are
            // legitimate WebAuthn origins but aren't subject to the RP ID/origin domain check.
            if (uri.Scheme is not ("http" or "https"))
                continue;

            var isLoopback = uri.IsLoopback || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase);

            if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase) && !isLoopback)
            {
                throw new Fido2ConfigurationException(
                    $"Configured origin '{origin}' does not use the https scheme. WebAuthn requires " +
                    "a potentially trustworthy origin; only loopback origins (e.g. http://localhost) may use http.");
            }

            var isSameHost = string.Equals(uri.Host, rpIdHost, StringComparison.OrdinalIgnoreCase);
            var isRegistrableSuffix = uri.Host.EndsWith("." + rpIdHost, StringComparison.OrdinalIgnoreCase);

            if (!isSameHost && !isRegistrableSuffix)
            {
                throw new Fido2ConfigurationException(
                    $"Configured origin '{origin}' has host '{uri.Host}', which is neither equal to nor a " +
                    $"registrable domain suffix of the configured RPID '{RPID}'.");
            }
        }
    }

    /// <summary>
    /// Whether to accept registration/authentication ceremonies performed inside a cross-origin
    /// iframe (i.e. where <c>collectedClientData.crossOrigin</c> is <see langword="true"/>), per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-terms">WebAuthn L3</see>. When
    /// <see langword="false"/> (the default), any response with <c>crossOrigin: true</c> is rejected.
    /// When <see langword="true"/>, a <c>topOrigin</c> present on the response is still required to
    /// match one of the configured <see cref="Origins"/>.
    /// </summary>
    public bool AllowCrossOriginRequests { get; set; }

    /// <summary>
    /// Metadata service cache directory path.
    /// </summary>
    public string MDSCacheDirPath { get; set; }

    /// <summary>
    /// List of metadata statuses for an authenticator that should cause attestations to be rejected.
    /// </summary>
    public AuthenticatorStatus[] UndesiredAuthenticatorMetadataStatuses { get; set; } =
    [
        AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE,
        AuthenticatorStatus.USER_VERIFICATION_BYPASS,
        AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE,
        AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE,
        AuthenticatorStatus.REVOKED
    ];

    /// <summary>
    /// How many sub-statements of a <c>compound</c> attestation statement must verify successfully.
    /// Defaults to <see cref="Fido2NetLib.CompoundAttestationPolicy.RequireAll"/>.
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation"/>
    /// </summary>
    public CompoundAttestationPolicy CompoundAttestationPolicy { get; set; } = CompoundAttestationPolicy.RequireAll;

    /// <summary>
    /// How to treat client or authenticator extension outputs that the Relying Party did not ask for.
    /// Defaults to <see cref="Fido2NetLib.UnsolicitedExtensionPolicy.Ignore"/>.
    /// </summary>
    /// <remarks>
    /// WebAuthn Level 3 permits clients to set extensions of their own accord: "Clients MAY set additional
    /// authenticator extensions or client extensions and thus cause values to appear in the authenticator extension
    /// outputs or client extension outputs that were not requested by the Relying Party [...] The Relying Party MUST
    /// be prepared to handle such situations, whether by ignoring the unsolicited extensions or by rejecting the
    /// attestation." Either behaviour is conformant, so this is a policy choice; ignoring is the default because
    /// rejecting fails registrations over outputs the Relying Party never depended on.
    /// See step 27 of <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential"/>.
    /// </remarks>
    public UnsolicitedExtensionPolicy UnsolicitedExtensionPolicy { get; set; } = UnsolicitedExtensionPolicy.Ignore;

    /// <summary>
    /// Whether or not to accept a backup eligible credential
    /// </summary>
    public CredentialBackupPolicy BackupEligibleCredentialPolicy { get; set; } = CredentialBackupPolicy.Allowed;

    /// <summary>
    /// Whether or not to accept a backed up credential
    /// </summary>
    public CredentialBackupPolicy BackedUpCredentialPolicy { get; set; } = CredentialBackupPolicy.Allowed;

#if NET9_0_OR_GREATER
    [JsonConverter(typeof(JsonStringEnumConverter<CredentialBackupPolicy>))]
#else
    [JsonConverter(typeof(FidoEnumConverter<CredentialBackupPolicy>))]
#endif
    public enum CredentialBackupPolicy
    {
        /// <summary>
        /// This value indicates that the Relying Party requires backup eligible or backed up credentials.
        /// </summary>
#if NET9_0_OR_GREATER
        [JsonStringEnumMemberName("required")]
#endif
        [EnumMember(Value = "required")]
        Required,

        /// <summary>
        /// This value indicates that the Relying Party allows backup eligible or backed up credentials.
        /// </summary>
#if NET9_0_OR_GREATER
        [JsonStringEnumMemberName("allowed")]
#endif
        [EnumMember(Value = "allowed")]
        Allowed,

        /// <summary>
        /// This value indicates that the Relying Party does not allow backup eligible or backed up credentials.
        /// </summary>
#if NET9_0_OR_GREATER
        [JsonStringEnumMemberName("disallowed")]
#endif
        [EnumMember(Value = "disallowed")]
        Disallowed
    }
}
