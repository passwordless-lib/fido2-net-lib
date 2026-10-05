#nullable disable

using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
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
    /// <remarks>
    /// WebAuthn L3 §15.1 recommends a range of 300000 to 600000 milliseconds and a default of 300000 (5
    /// minutes), citing WCAG 2.1 Guideline 2.2 "Enough Time". A client that judges a Relying Party's timeout not
    /// to meet that guideline MAY adjust it. The previous default here was 60000, well below the recommended
    /// range.
    /// </remarks>
    public uint Timeout { get; set; } = 300000;

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
    /// No longer part of WebAuthn: the icon member was removed from PublicKeyCredentialEntity in Level 2.
    /// </summary>
    [Obsolete("The icon member was removed from PublicKeyCredentialEntity in WebAuthn Level 2 and does not exist in Level 3; clients ignore it. This property will be removed in a future major version.")]
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
    /// Whether this Relying Party uses
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">related origin requests</see>, i.e.
    /// it serves the resource <see cref="GetWellKnownWebAuthn"/> builds and accepts ceremonies from origins
    /// that are not under <see cref="RPID"/>.
    /// </summary>
    /// <remarks>
    /// This relaxes <see cref="Validate"/> only. Origins must still be <c>https</c> (or loopback), and the
    /// per-ceremony origin comparison is unaffected -- an origin is accepted because it is in
    /// <see cref="Origins"/>, which is true either way.
    /// <para>
    /// Leave this <see langword="false"/> unless the well-known resource is actually being served: without
    /// it, a user agent rejects a ceremony from an origin outside <see cref="RPID"/>, and the startup check
    /// is what catches that before any user does.
    /// </para>
    /// </remarks>
    public bool AllowRelatedOrigins { get; set; }

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
    /// The host relationship is the whole point of related origin requests, so
    /// <see cref="AllowRelatedOrigins"/> turns that half of the check off. The scheme requirement is not
    /// relaxed: §5.11 changes which origins may share an RP ID, not which origins WebAuthn will talk to.
    /// <para>
    /// This is an opt-in, defense-in-depth sanity check on configuration -- it is not called
    /// automatically, and is not a substitute for the per-ceremony origin comparison performed in
    /// <c>AuthenticatorResponse.BaseVerify</c>, which remains the actual security boundary.
    /// Call it once at application startup (e.g. immediately after building a
    /// <see cref="Fido2Configuration"/>, or via <c>IValidateOptions&lt;Fido2Configuration&gt;</c>
    /// / <c>ValidateOnStart()</c> in ASP.NET Core) to fail fast on a misconfigured
    /// <see cref="Origins"/>/<see cref="RPID"/> pair, per WebAuthn L3 §13.4.9.
    /// </para>
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

            // Related origin requests exist so that a Relying Party can share one RP ID across origins that
            // have no domain relationship to it at all, so this is the one check they turn off.
            if (AllowRelatedOrigins)
                continue;

            var isSameHost = string.Equals(uri.Host, rpIdHost, StringComparison.OrdinalIgnoreCase);
            var isRegistrableSuffix = uri.Host.EndsWith("." + rpIdHost, StringComparison.OrdinalIgnoreCase);

            if (!isSameHost && !isRegistrableSuffix)
            {
                throw new Fido2ConfigurationException(
                    $"Configured origin '{origin}' has host '{uri.Host}', which is neither equal to nor a " +
                    $"registrable domain suffix of the configured RPID '{RPID}'. If this Relying Party serves " +
                    $"/.well-known/webauthn for related origin requests, set {nameof(AllowRelatedOrigins)}.");
            }
        }
    }

    /// <summary>
    /// Whether to accept registration/authentication ceremonies performed inside a cross-origin
    /// iframe (i.e. where <c>collectedClientData.crossOrigin</c> is <see langword="true"/>), per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-iframe-guidance">WebAuthn L3</see>. When
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
    /// The trust anchor used to validate the certificate chain of the <c>apple</c> anonymous attestation format.
    /// Apple platform authenticators are not in the FIDO Metadata Service, so their chain is validated against
    /// this root rather than metadata. Defaults to Apple's published WebAuthn root when left <see langword="null"/>;
    /// override it only to pin a different root (for example in tests).
    /// </summary>
    [JsonIgnore]
    public X509Certificate2 AppleWebAuthnRootCertificate { get; set; }

    /// <summary>
    /// The trust anchor used to validate the certificate chain of the <c>android-safetynet</c> attestation
    /// format. Google's SafetyNet root is not in the FIDO Metadata Service, so its chain is validated against
    /// this root rather than metadata. Defaults to Google Trust Services root R1 when left <see langword="null"/>;
    /// override it only to pin a different root (for example in tests). Note that <c>android-safetynet</c> is
    /// deprecated.
    /// </summary>
    [JsonIgnore]
    public X509Certificate2 AndroidSafetyNetRootCertificate { get; set; }

    /// <summary>
    /// The trust anchors the FIDO Metadata Service BLOB signing certificate chain must terminate at. Defaults to
    /// GlobalSign Root CA - R3 and GlobalSign Root R46 when left <see langword="null"/> or empty (both are
    /// currently valid termini: the BLOB's chain includes a copy of R46 cross-signed by R3, and platforms differ
    /// on which one their own trust store already carries directly -- see
    /// <see href="https://github.com/passwordless-lib/fido2-net-lib/issues/517"/>). Override only to pin different
    /// root(s), for example if FIDO Alliance rotates roots again before this library ships an update, or against a
    /// self-hosted/enterprise MDS mirror with its own signing chain.
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<X509Certificate2> MdsRootCertificates { get; set; }

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
    /// AAGUIDs of authenticator models that are always rejected, regardless of their MDS status.
    /// Checked at registration, and at assertion for any credential whose AAGUID the caller supplies
    /// (<c>MakeAssertionParams.StoredAaGuid</c>).
    /// </summary>
    /// <remarks>
    /// The AAGUID is reported by the authenticator itself, so a deny list stops a model that identifies
    /// itself honestly -- the usual case for a recalled or unwanted product -- but not an authenticator (or a
    /// modified client) that lies about its AAGUID. Keeping out authenticators that might lie takes an
    /// <see cref="AaguidAllowList"/> with <see cref="AaguidAllowListRequiresAttestation"/>, which only accepts
    /// an AAGUID the attestation statement proves.
    /// <para>
    /// A <see cref="HashSet{T}"/> rather than an interface so that <c>Microsoft.Extensions.Configuration</c> can
    /// bind it from settings (e.g. <c>"AaguidDenyList": [ "cb69481e-8ff7-4039-93ec-0a2729a154a8" ]</c>); the
    /// binder leaves <c>ISet&lt;Guid&gt;</c> and <c>IReadOnlySet&lt;Guid&gt;</c> properties empty.
    /// </para>
    /// </remarks>
    public HashSet<Guid> AaguidDenyList { get; set; } = [];

    /// <summary>
    /// AAGUIDs of authenticator models that may register. Empty (the default) means no restriction.
    /// </summary>
    /// <remarks>
    /// Only enforced at registration; narrowing the list does not retroactively block credentials registered
    /// before it changed. To withdraw a model from existing users, add it to <see cref="AaguidDenyList"/>,
    /// which is also enforced at sign-in.
    /// <para>
    /// While <see cref="AaguidAllowListRequiresAttestation"/> is <see langword="true"/> (the default), an
    /// AAGUID on the list is only accepted when the attestation proves it, so registration options must ask for
    /// attestation (<see cref="Fido2NetLib.Objects.AttestationConveyancePreference.Direct"/> or
    /// <see cref="Fido2NetLib.Objects.AttestationConveyancePreference.Enterprise"/>) and a metadata service must be configured.
    /// </para>
    /// </remarks>
    public HashSet<Guid> AaguidAllowList { get; set; } = [];

    /// <summary>
    /// Whether an AAGUID on a non-empty <see cref="AaguidAllowList"/> is only accepted when the attestation
    /// proves it. Defaults to <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// An AAGUID is proven when the attestation is a basic or attestation-CA attestation (<c>AttestationType.Basic</c>
    /// or <c>AttestationType.AttCa</c>) and its certificate chain was validated against
    /// the attestation roots in that model's FIDO Metadata Service statement. Without that, the AAGUID is
    /// whatever the authenticator chose to send: under <c>none</c> or self attestation any software
    /// authenticator can claim an allowed model's AAGUID. Set this to <see langword="false"/> only when the
    /// allow list is a user-experience filter rather than a security control.
    /// </remarks>
    public bool AaguidAllowListRequiresAttestation { get; set; } = true;

    /// <summary>
    /// Whether to re-check <see cref="UndesiredAuthenticatorMetadataStatuses"/> at assertion time, not only at
    /// registration, for any credential whose AAGUID the caller supplies (<c>MakeAssertionParams.StoredAaGuid</c>).
    /// Off by default, since it adds a metadata lookup to every authentication rather than only to registration.
    /// </summary>
    /// <remarks>
    /// Like the registration-time check, this only acts on a status report the metadata service actually has:
    /// an authenticator model with no metadata entry (most synced passkey providers) passes, and so does every
    /// credential when the metadata service cannot be reached. FIDO U2F authenticators have no AAGUID -- their
    /// metadata is keyed by attestation certificate -- so they are not re-checked. A call without
    /// <c>StoredAaGuid</c> skips the re-check and logs a warning (event 1204).
    /// </remarks>
    public bool RecheckMetadataStatusOnAssertion { get; set; }

    /// <summary>
    /// Configuration for resolving display-only authenticator names/icons by AAGUID (for UI, logs, and admin
    /// tooling), separate from the signed FIDO Metadata Service used above for trust decisions. Read by
    /// <c>AddAuthenticatorDisplayMetadata()</c> in Fido2.AspNet.
    /// </summary>
    public DisplayMetadataOptions DisplayMetadata { get; set; } = new();

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
    /// See step 28 of <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential"/>.
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

    /// <summary>
    /// How strictly to reject a ceremony whose attestation or assertion contradicts what the authenticator's own
    /// FIDO Metadata Service statement says it is capable of. Defaults to <see cref="Fido2NetLib.MetadataConsistencyStrictness.Standard"/>.
    /// </summary>
    /// <remarks>
    /// Most checks only make sense at registration -- algorithm, credential ID length and discoverability are
    /// fixed for the credential's lifetime, so there is nothing new to learn about them at assertion. The
    /// assertion-time checks below exist because a handful of properties genuinely can disagree with what was
    /// true at registration, and because WebAuthn gives a Relying Party less to work with at assertion than at
    /// registration -- notably, there is no assertion-time equivalent of <c>getTransports()</c> at all, so an
    /// actual transport-for-this-login check is not something this library (or any other) can implement; the
    /// closest available signal is <c>authenticatorAttachment</c>, which is checked instead, with the caveats
    /// described below. Every check, at either ceremony, is skipped entirely when the AAGUID has no metadata
    /// entry: a model with no statement has claimed nothing to contradict. (Contrast
    /// <see cref="RecheckMetadataStatusOnAssertion"/>, which re-checks revocation status -- a different kind of
    /// property, a per-model judgement from the FIDO Alliance rather than a per-credential capability claim.)
    /// <para>
    /// <b>Strong-tier checks</b> (reject at <see cref="Fido2NetLib.MetadataConsistencyStrictness.Standard"/> and above), <i>registration only</i>:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <b>Algorithm.</b> For a FIDO2 statement that declares <c>authenticatorGetInfo.algorithms</c>, the
    /// credential's COSE algorithm must be one of them.
    /// </description></item>
    /// <item><description>
    /// <b>Credential ID length.</b> The credential ID must not exceed the statement's declared
    /// <c>authenticatorGetInfo.maxCredentialIdLength</c>, when present.
    /// </description></item>
    /// <item><description>
    /// <b>Discoverability.</b> The <c>credProps.rk</c> extension output must not claim a discoverable credential
    /// was created when the statement's <c>authenticatorGetInfo.options.rk</c> is explicitly <see langword="false"/>.
    /// </description></item>
    /// </list>
    /// <para>
    /// <b>Weak-tier checks</b> (logged always; reject only at <see cref="Fido2NetLib.MetadataConsistencyStrictness.Strict"/>):
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <b>Backup eligibility</b> (registration). The statement's <c>multiDeviceCredentialSupport</c> is
    /// <c>"unsupported"</c>, <c>"explicit"</c> or <c>"implicit"</c>, and "if this field is missing the implicit
    /// value is <c>unsupported</c>" (FIDO Metadata Statement v3.1 §4) -- so a BE credential from a model whose
    /// statement says or, by omission, implies <c>"unsupported"</c> is claiming a capability its own statement
    /// denies. Weak tier specifically because of that omission case: most statements in the live BLOB predate
    /// this field, so treating a missing field as a contradiction -- which is the spec's own reading -- would
    /// reject BE credentials from most real, honest models if it blocked by default.
    /// </description></item>
    /// <item><description>
    /// <b>Backup state</b> (assertion). The same check as backup eligibility above, applied to the BS flag on
    /// every assertion rather than only the BE flag at registration. BE is fixed for a credential's lifetime and
    /// already checked for agreement with the stored value elsewhere; BS is not -- a credential can start backing
    /// up (e.g. synced into a cloud keychain) well after registration, which is exactly the case this check is
    /// for: a hardware authenticator whose statement denies multi-device support should not suddenly show up
    /// backed up. Requires <c>MakeAssertionParams.StoredAaGuid</c>; skipped without it.
    /// </description></item>
    /// <item><description>
    /// <b>Transports</b> (registration). The client's reported <c>getTransports()</c> values should be a subset
    /// of the statement's <c>authenticatorGetInfo.transports</c>, when declared. Real authenticators --
    /// especially cross-device/hybrid flows and synced credential providers -- are known to report transports
    /// inconsistently with their own metadata in ordinary, non-malicious use, hence weak tier.
    /// </description></item>
    /// <item><description>
    /// <b>Attachment</b> (assertion). WebAuthn has no assertion-time equivalent of <c>getTransports()</c> --
    /// <c>AuthenticatorAttestationResponse.getTransports()</c> exists only on the registration response -- so
    /// this is the closest available proxy for "did this login use a transport the statement doesn't mention":
    /// the reported <c>authenticatorAttachment</c> (<c>"platform"</c> or <c>"cross-platform"</c>) is checked for
    /// agreement with the statement's <c>authenticatorGetInfo.transports</c> (<c>"platform"</c> requires
    /// <c>"internal"</c> to be declared; <c>"cross-platform"</c> requires at least one non-<c>"internal"</c>
    /// transport). This is a coarser signal than a real transport check and the client-supplied value it relies
    /// on is, per <see cref="Fido2NetLib.Objects.AuthenticatorAttachment"/>'s own remarks, "informational only" and never part of the
    /// signed assertion -- weak tier reflects that explicitly, on top of the usual honest-disagreement reasoning.
    /// Requires <c>MakeAssertionParams.StoredAaGuid</c>; skipped without it, or when the client reported no
    /// attachment.
    /// </description></item>
    /// <item><description>
    /// <b>Extensions</b> (registration and assertion). An authenticator-level extension output (<c>credProtect</c>,
    /// <c>credBlob</c>, <c>minPinLength</c>, and <c>prf</c>/<c>largeBlob</c> via their CTAP2 counterparts
    /// <c>hmac-secret</c>/<c>largeBlobKey</c>) should appear in the statement's <c>supportedExtensions</c> or
    /// <c>authenticatorGetInfo.extensions</c>. MDS extension declarations are known to be incomplete for many
    /// statements, hence weak tier. Client-only extension outputs that an authenticator statement would never
    /// declare (<c>credProps</c> itself, legacy <c>exts</c>/<c>uvm</c>) are not checked. Checked at assertion only
    /// when <c>MakeAssertionParams.StoredAaGuid</c> is supplied.
    /// </description></item>
    /// </list>
    /// </remarks>
    public MetadataConsistencyStrictness MetadataConsistencyStrictness { get; set; } = MetadataConsistencyStrictness.Standard;

    /// <summary>
    /// What the relying party requires of a credential's backup eligibility (BE) and backup state (BS) flags.
    /// </summary>
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
