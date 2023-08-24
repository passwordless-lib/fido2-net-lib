﻿using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Fido2NetLib;

/// <summary>
/// Represents the MetadataBLOBPayload
/// </summary>
/// <remarks>
/// <see xref="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary"/>
/// </remarks>
public sealed class MetadataBLOBPayload
{
    /// <summary>
    /// Gets or sets the legalHeader, if present, contains a legal guide for accessing and using metadata.
    /// </summary>
    /// <remarks>
    /// This value MAY contain URL(s) pointing to further information, such as a full Terms and Conditions statement. 
    /// </remarks>
    [JsonPropertyName("legalHeader")]
    public string LegalHeader { get; set; }

    /// <summary>   
    /// Gets or sets the serial number of this UAF Metadata BLOB Payload. 
    /// </summary>
    /// <remarks>
    /// Serial numbers MUST be consecutive and strictly monotonic, i.e. the successor BLOB will have a no value exactly incremented by one.
    /// </remarks>
    [JsonPropertyName("no"), Required]
    public int Number { get; set; }

    /// <summary>
    /// Gets or sets a formatted date (ISO-8601) when the next update will be provided at latest.
    /// </summary>
    [JsonPropertyName("nextUpdate"), Required]
    public string NextUpdate { get; set; }

    /// <summary>
    /// Gets or sets a list of zero or more entries of <see cref="MetadataBLOBPayloadEntry"/>.
    /// </summary>
    [JsonPropertyName("entries"), Required]
    public MetadataBLOBPayloadEntry[] Entries { get; set; }

    /// <summary>
    /// The "alg" property from the original JWT header. Used to validate MetadataStatements.
    /// </summary>
    [JsonPropertyName("jwtAlg")]
    public string JwtAlg { get; set; }
}
