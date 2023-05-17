using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

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
    public string ServerDomain { get; set; }

    /// <summary>
    /// A human-friendly name of the RP.
    /// </summary>
    public string ServerName { get; set; }

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
            if (_origins == null)
            {
                _origins = new HashSet<string>(0);
            }

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
    /// Metadata service cache directory path.
    /// </summary>
    public string MDSCacheDirPath { get; set; }

    /// <summary>
    /// List of metadata statuses for an authenticator that should cause attestations to be rejected.
    /// </summary>
    public AuthenticatorStatus[] UndesiredAuthenticatorMetadataStatuses { get; set; } = new AuthenticatorStatus[]
    {
        AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE,
        AuthenticatorStatus.USER_VERIFICATION_BYPASS,
        AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE,
        AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE,
        AuthenticatorStatus.REVOKED
    };

    /// <summary>
    /// Whether or not to accept a backup eligible credential
    /// </summary>
    public CredentialBackupPolicy BackupEligibleCredentialPolicy { get; set; } = CredentialBackupPolicy.Allowed;

    /// <summary>
    /// Whether or not to accept a backed up credential
    /// </summary>
    public CredentialBackupPolicy BackedUpCredentialPolicy { get; set; } = CredentialBackupPolicy.Allowed;

    public enum CredentialBackupPolicy
    {
        /// <summary>
        /// This value indicates that the Relying Party requires backup eligible or backed up credentials.
        /// </summary>
        [EnumMember(Value = "required")]
        Required,

        /// <summary>
        /// This value indicates that the Relying Party allows backup eligible or backed up credentials.
        /// </summary>
        [EnumMember(Value = "allowed")]
        Allowed,

        /// <summary>
        /// This value indicates that the Relying Party does not allow backup eligible or backed up credentials.
        /// </summary>
        [EnumMember(Value = "disallowed")]
        Disallowed
    }
}
