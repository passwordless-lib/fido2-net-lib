namespace Fido2NetLib.Objects;

using System;
using System.Text.Json.Serialization;

/// <summary>
///  Deprecated: DevicePublickeyKey has been deprecated but is kept around in the code base because of conformance testing tools.
/// </summary>
public sealed class AuthenticationExtensionsDevicePublicKeyInputs
{
    [JsonPropertyName("attestation")]
    public string Attestation { get; set; } = "none";

    [JsonPropertyName("attestationFormats")]
    public IReadOnlyList<AttestationStatementFormatIdentifier> AttestationFormats { get; set; } = Array.Empty<AttestationStatementFormatIdentifier>();
}
