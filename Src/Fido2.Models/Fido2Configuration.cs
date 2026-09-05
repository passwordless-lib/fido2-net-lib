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
