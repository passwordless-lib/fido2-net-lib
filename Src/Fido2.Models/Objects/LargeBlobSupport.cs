using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace Fido2NetLib.Objects;

/// <summary>
/// The possible values for requesting the largeBlob extension during credential registration.
/// 
/// https://w3c.github.io/webauthn/#sctn-large-blob-extension
/// </summary>
[JsonConverter(typeof(FidoEnumConverter<LargeBlobSupport>))]
public enum LargeBlobSupport
{
    /// <summary>
    /// largeBlob support is required -- credential creation will fail if largeBlob is not supported
    /// </summary>
    [EnumMember(Value = "required")] Required,
    
    /// <summary>
    /// largeBlob support is preferred -- credential creation will succeed even if largeBlob is not supported.
    /// </summary>
    [EnumMember(Value = "preferred")] Preferred
}
