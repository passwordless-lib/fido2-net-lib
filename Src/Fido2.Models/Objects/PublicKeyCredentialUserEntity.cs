#nullable enable

using System;

namespace Fido2NetLib.Objects;

public sealed class PublicKeyCredentialUserEntity
{
    public PublicKeyCredentialUserEntity(byte[] id, string name, string displayName, string? icon = null)
    {
        ArgumentNullException.ThrowIfNull(id);
        
        if (id.Length is 0)
        {
            throw new ArgumentException($"Must not be empty", nameof(id));
        }

        if (id.Length > 64)
        {
            throw new ArgumentException($"Must be 64 bytes or fewer. Was {id.Length} bytes", nameof(id));
        }

        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(displayName);

        Id = id;
        Name = name;
        DisplayName = displayName;
        Icon = icon;
    }

    /// <summary>
    /// The user handle of the user account entity. 
    /// A user handle is an opaque byte sequence with a maximum size of 64 bytes, and is not meant to be displayed to the user.
    /// The user handle MUST NOT contain personally identifying information about the user, such as a username or e-mail address.
    /// </summary>
    public byte[] Id { get; }

    public string Name { get; }

    /// <summary>
    /// A human-palatable name for the user account, intended only for display. For example, "Alex Müller" or "田中倫".
    /// </summary>
    public string DisplayName { get; }

    public string? Icon { get; }
}

// https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialentity
