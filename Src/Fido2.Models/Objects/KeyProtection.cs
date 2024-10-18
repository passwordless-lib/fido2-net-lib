using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/**
 * Key Protection Types Short Form
 *
 * The KEY_PROTECTION constants are flags in a bit field represented as a 16 bit long integer. They describe the method an authenticator uses to protect the private key material for FIDO registrations. Refer to [UAFAuthnrCommands] for more details on the relevance of keys and key protection. These constants are used in the authoritative metadata for an authenticator, reported and queried through the UAF Discovery APIs, and used to form authenticator policies in UAF protocol messages.
 *
 * https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-reg-v1.0-ps-20141208.html#key-protection-types
 * type {Object}
 */
[JsonConverter(typeof(FidoEnumConverter<KeyProtection>))]
public enum KeyProtection
{
    /// <summary>
    /// This flag must be set if the authenticator uses software-based key management. Exclusive in authenticator metadata with KEY_PROTECTION_HARDWARE, KEY_PROTECTION_TEE, KEY_PROTECTION_SECURE_ELEMENT
    /// </summary>
    [EnumMember(Value = "software")]
    SOFTWARE = 1,
    /// <summary>
    /// This flag should be set if the authenticator uses hardware-based key management. Exclusive in authenticator metadata with KEY_PROTECTION_SOFTWARE
    /// </summary>
    [EnumMember(Value = "hardware")]
    HARDWARE = 2,
    /// <summary>
    /// This flag should be set if the authenticator uses the Trusted Execution Environment [TEE] for key management. In authenticator metadata, this flag should be set in conjunction with KEY_PROTECTION_HARDWARE. Exclusive in authenticator metadata with KEY_PROTECTION_SOFTWARE, KEY_PROTECTION_SECURE_ELEMENT
    /// </summary>
    [EnumMember(Value = "tee")]
    TEE = 4,
    /// <summary>
    /// This flag should be set if the authenticator uses a Secure Element [SecureElement] for key management. In authenticator metadata, this flag should be set in conjunction with KEY_PROTECTION_HARDWARE. Exclusive in authenticator metadata with KEY_PROTECTION_TEE, KEY_PROTECTION_SOFTWARE
    /// </summary>
    [EnumMember(Value = "secure_element")]
    SECURE_ELEMENT = 0x8,
    /// <summary>
    /// This flag must be set if the authenticator does not store (wrapped) UAuth keys at the client, but relies on a server-provided key handle. This flag must be set in conjunction with one of the other KEY_PROTECTION flags to indicate how the local key handle wrapping key and operations are protected. Servers may unset this flag in authenticator policy if they are not prepared to store and return key handles, for example, if they have a requirement to respond indistinguishably to authentication attempts against userIDs that do and do not exist. Refer to [UAFProtocol] for more details.
    /// </summary>
    [EnumMember(Value = "remote_handle")]
    REMOTE_HANDLE = 0x10,
}
