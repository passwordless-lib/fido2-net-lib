using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

namespace Fido2NetLib;

/// <summary>
/// Queries an ordered list of <see cref="IAuthenticatorDisplayMetadataService"/> sources and merges their answers
/// field by field: each field comes from the first source that has it, so a Relying Party's own local file (listed
/// first) overrides the <see cref="ConvenienceMetadataService"/> (listed after it), which fills in the rest.
/// </summary>
/// <remarks>
/// A source that throws is logged (event ID 1305) and skipped, so one failing source cannot take the others down
/// with it. <c>AddAuthenticatorDisplayMetadata()</c> in Fido2.AspNet registers one of these, built from
/// <see cref="Fido2Configuration.DisplayMetadata"/>.
/// </remarks>
/// <param name="sources">The sources to query, in priority order.</param>
/// <param name="logger">Where a failing source is reported, or <see langword="null"/>.</param>
public sealed class CompositeAuthenticatorDisplayMetadataService(
    IReadOnlyList<IAuthenticatorDisplayMetadataService> sources,
    ILogger<CompositeAuthenticatorDisplayMetadataService>? logger = null) : IAuthenticatorDisplayMetadataService
{
    /// <summary>
    /// The sources, in priority order.
    /// </summary>
    public IReadOnlyList<IAuthenticatorDisplayMetadataService> Sources { get; } = sources ?? throw new ArgumentNullException(nameof(sources));

    /// <inheritdoc/>
    public async Task<AuthenticatorDisplayInfo?> GetDisplayInfoAsync(Guid aaguid, CancellationToken cancellationToken = default)
    {
        string? name = null;
        string? iconLight = null;
        string? iconDark = null;
        IReadOnlyDictionary<string, string>? friendlyNames = null;
        bool foundAny = false;

        foreach (var source in Sources)
        {
            AuthenticatorDisplayInfo? info;
            try
            {
                info = await source.GetDisplayInfoAsync(aaguid, cancellationToken);
            }
            catch (Exception ex) when (!(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
            {
                logger?.SourceFailed(ex, source.GetType().Name);
                continue;
            }

            if (info is null)
                continue;

            foundAny = true;
            name ??= info.Name;
            iconLight ??= info.IconLight;
            iconDark ??= info.IconDark;
            friendlyNames ??= info.FriendlyNames;
        }

        return foundAny ? new AuthenticatorDisplayInfo(name, iconLight, iconDark) { FriendlyNames = friendlyNames } : null;
    }
}
