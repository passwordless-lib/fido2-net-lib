using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Describes the status of an authenticator model as identified by its AAID and potentially some additional information (such as a specific attestation key).
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#authenticatorstatus-enum"/>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<AuthenticatorStatus>))]
public enum AuthenticatorStatus
{
    /// <summary>
    /// This authenticator is not FIDO certified.
    /// </summary>
    NOT_FIDO_CERTIFIED,
    /// <summary>
    /// This authenticator has passed FIDO functional certification.
    /// <para>
    /// This certification scheme is phased out and will be replaced by FIDO_CERTIFIED_L1.
    /// </para>
    /// </summary>
    FIDO_CERTIFIED,
    /// <summary>
    /// Indicates that malware is able to bypass the user verification.
    /// <para>This means that the authenticator could be used without the user's consent and potentially even without the user's knowledge.</para>
    /// </summary>
    USER_VERIFICATION_BYPASS,
    /// <summary>
    /// Indicates that an attestation key for this authenticator is known to be compromised.
    /// </summary>
    /// <remarks>
    /// Additional data should be supplied, including the key identifier and the date of compromise, if known.
    /// </remarks>
    ATTESTATION_KEY_COMPROMISE,
    /// <summary>
    /// This authenticator has identified weaknesses that allow registered keys to be compromised and should not be trusted.
    /// <para>This would include both, e.g. weak entropy that causes predictable keys to be generated or side channels that allow keys or signatures to be forged, guessed or extracted.</para>
    /// </summary>
    USER_KEY_REMOTE_COMPROMISE,
    /// <summary>
    /// This authenticator has known weaknesses in its key protection mechanism(s) that allow user keys to be extracted by an adversary in physical possession of the device.
    /// </summary>
    USER_KEY_PHYSICAL_COMPROMISE,
    /// <summary>
    /// A software or firmware update is available for the device.
    /// </summary>
    UPDATE_AVAILABLE,
    /// <summary>
    /// The FIDO Alliance has determined that this authenticator should not be trusted.
    /// </summary>
    /// <remarks>
    /// For example: if it is known to be a fraudulent product or contain a deliberate backdoor.
    /// </remarks>
    REVOKED,
    /// <summary>
    /// The authenticator vendor has completed and submitted the self-certification checklist to the FIDO Alliance.
    /// </summary>
    /// <remarks>
    /// If this completed checklist is publicly available, the URL will be specified in <see cref="StatusReport.Url"/>.
    /// </remarks>
    SELF_ASSERTION_SUBMITTED,
    /// <summary>
    /// The authenticator has passed FIDO Authenticator certification at level 1. This level is the more strict successor of FIDO_CERTIFIED.
    /// </summary>
    FIDO_CERTIFIED_L1,
    /// <summary>
    /// The authenticator has passed FIDO Authenticator certification at level 1+. This level is the more than level <see cref="FIDO_CERTIFIED_L1"/>.
    /// </summary>
    FIDO_CERTIFIED_L1plus,
    /// <summary>
    /// The authenticator has passed FIDO Authenticator certification at level 2. This level is more strict than level <see cref="FIDO_CERTIFIED_L1plus"/>.
    /// </summary>
    FIDO_CERTIFIED_L2,
    /// <summary>
    /// The authenticator has passed FIDO Authenticator certification at level 2+. This level is more strict than level <see cref="FIDO_CERTIFIED_L2"/>.
    /// </summary>
    FIDO_CERTIFIED_L2plus,
    /// <summary>
    /// The authenticator has passed FIDO Authenticator certification at level 3. This level is more strict than level <see cref="FIDO_CERTIFIED_L2plus"/>.
    /// </summary>
    FIDO_CERTIFIED_L3,
    /// <summary>
    /// The authenticator has passed FIDO Authenticator certification at level 3+. This level is more strict than level <see cref="FIDO_CERTIFIED_L3"/>.
    /// </summary>
    FIDO_CERTIFIED_L3plus
};
