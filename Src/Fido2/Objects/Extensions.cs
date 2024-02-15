using System;

namespace Fido2NetLib.Objects;

/// <summary>
/// <see href="https://www.w3.org/TR/webauthn/#extensions"/>
/// </summary>
public sealed class Extensions
{
    private readonly byte[] _extensionBytes;

    public Extensions(byte[] extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);

        _extensionBytes = extensions;
    }

    public int Length => _extensionBytes.Length;

    public byte[] GetBytes()
    {
        return _extensionBytes;
    }
}
