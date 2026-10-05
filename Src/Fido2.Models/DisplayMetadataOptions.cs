using System;

namespace Fido2NetLib;

/// <summary>
/// Where display-only authenticator names and icons come from, resolved by AAGUID for UI, logs and admin tooling.
/// Separate from the signed FIDO Metadata Service used for trust decisions. See
/// <see cref="Fido2Configuration.DisplayMetadata"/>; <c>AddAuthenticatorDisplayMetadata()</c> in Fido2.AspNet
/// registers the sources configured here.
/// </summary>
public sealed class DisplayMetadataOptions
{
    /// <summary>
    /// The FIDO Alliance Convenience Metadata Service, the default <see cref="ConvenienceMetadataServiceUrl"/>.
    /// </summary>
    public static readonly Uri DefaultConvenienceMetadataServiceUrl = new("https://c-mds.fidoalliance.org/");

    /// <summary>
    /// Whether to download names and icons from the FIDO Alliance Convenience Metadata Service. Off by default,
    /// since it means a periodic download of a multi-megabyte document from a third-party service.
    /// </summary>
    public bool UseConvenienceMetadataService { get; set; }

    /// <summary>
    /// Where the Convenience Metadata Service document is downloaded from. Defaults to
    /// <see cref="DefaultConvenienceMetadataServiceUrl"/>.
    /// </summary>
    public Uri ConvenienceMetadataServiceUrl { get; set; } = DefaultConvenienceMetadataServiceUrl;

    /// <summary>
    /// The path to a local display-metadata JSON file in the
    /// <see href="https://github.com/passkeydeveloper/passkey-authenticator-aaguids">passkey-authenticator-aaguids</see>
    /// shape, or <see langword="null"/> for none. Its entries take priority over the Convenience Metadata Service,
    /// field by field.
    /// </summary>
    public string? LocalFilePath { get; set; }

    /// <summary>
    /// How long a downloaded copy of the Convenience Metadata Service document is used before checking for a newer
    /// one. The check is conditional on the copy's serial number, so an unchanged document is not downloaded again.
    /// Defaults to one day.
    /// </summary>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// How long to wait after a failed download before trying again. Until then lookups are answered from the last
    /// good copy, or return nothing, rather than each retrying the download. Defaults to one hour.
    /// </summary>
    public TimeSpan RetryAfterFailure { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// The largest Convenience Metadata Service document that will be downloaded, in bytes. Defaults to 32 MiB;
    /// the document was about 5 MB in 2026.
    /// </summary>
    public long MaxDocumentBytes { get; set; } = 32 * 1024 * 1024;
}
