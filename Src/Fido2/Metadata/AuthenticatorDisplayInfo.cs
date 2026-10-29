using System;
using System.Collections.Generic;
using System.Linq;

namespace Fido2NetLib;

/// <summary>
/// A friendly name and icon(s) for an authenticator model, resolved by AAGUID from an unsigned, display-only
/// source. Unlike <see cref="MetadataStatement"/>, this carries no trust information and must never be
/// consulted by attestation or assertion verification -- it exists purely for labeling AAGUIDs in UI, logs,
/// and admin tooling.
/// </summary>
/// <remarks>
/// The sources are third-party data. The library only passes on icons that are <c>data:</c> URLs of an image
/// type and names without control characters, but a page showing them must still HTML-encode the name and put
/// icons only in an <c>&lt;img src&gt;</c> (where an SVG cannot run script), never inline them into the page.
/// </remarks>
/// <param name="Name">The authenticator's display name (English where the source offers it), or <see langword="null"/> if unknown.</param>
/// <param name="IconLight">A <c>data:image/...</c> URL icon for use on a light background, or <see langword="null"/> if unavailable.</param>
/// <param name="IconDark">A <c>data:image/...</c> URL icon for use on a dark background, or <see langword="null"/> if unavailable.</param>
public sealed record AuthenticatorDisplayInfo(string? Name, string? IconLight, string? IconDark)
{
    /// <summary>
    /// The display name in every language the source offers, keyed by IETF language tag (e.g. <c>en-US</c>), or
    /// <see langword="null"/> if the source offers only <see cref="Name"/>.
    /// </summary>
    public IReadOnlyDictionary<string, string>? FriendlyNames { get; init; }

    private const int MaxNameLength = 128;
    private const int MaxIconLength = 1024 * 1024;

    private static readonly string[] s_allowedIconPrefixes =
    [
        "data:image/svg+xml;", "data:image/svg+xml,",
        "data:image/png;", "data:image/png,",
        "data:image/jpeg;", "data:image/gif;", "data:image/webp;"
    ];

    /// <summary>
    /// A name fit to display: trimmed, without control characters, and no longer than 128 characters; or
    /// <see langword="null"/> when nothing is left.
    /// </summary>
    internal static string? SanitizeName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return null;

        var cleaned = new string(name.Where(c => !char.IsControl(c)).ToArray()).Trim();

        if (cleaned.Length > MaxNameLength)
            cleaned = cleaned[..MaxNameLength];

        return cleaned.Length == 0 ? null : cleaned;
    }

    /// <summary>
    /// The icon if it is a <c>data:</c> URL of an image type no larger than 1 MiB, otherwise <see langword="null"/> --
    /// so a source cannot hand a page a <c>javascript:</c> or remote URL to embed.
    /// </summary>
    internal static string? SanitizeIcon(string? icon)
    {
        if (string.IsNullOrEmpty(icon) || icon.Length > MaxIconLength)
            return null;

        foreach (var prefix in s_allowedIconPrefixes)
        {
            if (icon.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return icon;
        }

        return null;
    }

    /// <summary>
    /// The English name from a set of localized names: <c>en-US</c>, then any other <c>en</c> tag, then the first.
    /// </summary>
    internal static string? PickName(IReadOnlyDictionary<string, string>? friendlyNames)
    {
        if (friendlyNames is null || friendlyNames.Count == 0)
            return null;

        if (friendlyNames.TryGetValue("en-US", out var enUs) && SanitizeName(enUs) is { } name)
            return name;

        foreach (var (tag, value) in friendlyNames)
        {
            if ((tag.Equals("en", StringComparison.OrdinalIgnoreCase) || tag.StartsWith("en-", StringComparison.OrdinalIgnoreCase)) &&
                SanitizeName(value) is { } english)
            {
                return english;
            }
        }

        foreach (var value in friendlyNames.Values)
        {
            if (SanitizeName(value) is { } any)
                return any;
        }

        return null;
    }
}
