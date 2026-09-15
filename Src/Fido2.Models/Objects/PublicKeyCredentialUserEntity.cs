#nullable disable

using System;
using System.ComponentModel.DataAnnotations;

namespace Fido2NetLib.Objects;

public sealed class PublicKeyCredentialUserEntity
{
#pragma warning disable IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code
    [MinLength(1)]
    [MaxLength(64)]
    public byte[] Id { get; set; }
#pragma warning restore IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code

    public string Name { get; set; }

    public string DisplayName { get; set; }

    /// <summary>
    /// No longer part of WebAuthn.
    /// </summary>
    [Obsolete("The icon member was removed from PublicKeyCredentialEntity in WebAuthn Level 2 and does not exist in Level 3; clients ignore it. This member will be removed in a future major version.")]
    public string Icon { get; set; }
}
