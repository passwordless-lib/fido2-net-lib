using System.Text.Json;

using Fido2NetLib;
using Fido2NetLib.Serialization;

using Xunit;

namespace Fido2NetLib.Models.Tests;

/// <summary>
/// Serialization contract tests for the <see cref="StatusReport"/> fields and
/// <see cref="AuthenticatorStatus"/> values defined by FIDO Metadata Service v3.1.1.
/// </summary>
public class StatusReportSerializationTests
{
    [Fact]
    public void Deserializes_Fips_Status_Report_Using_Spec_Wire_Names()
    {
        const string json = """
        {
            "status": "FIPS140_CERTIFIED_L2",
            "effectiveDate": "2026-01-05",
            "authenticatorVersion": 7,
            "certificateNumber": "4321",
            "url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4321",
            "sunsetDate": "2031-01-05",
            "fipsRevision": 3,
            "fipsPhysicalSecurityLevel": 3
        }
        """;

        var report = JsonSerializer.Deserialize<StatusReport>(json);

        Assert.NotNull(report);
        Assert.Equal(AuthenticatorStatus.FIPS140_CERTIFIED_L2, report!.Status);
        Assert.Equal(7UL, report.AuthenticatorVersion);
        Assert.Equal("2031-01-05", report.SunsetDate);
        Assert.Equal(3UL, report.FipsRevision);

        // The physical security level may differ from the overall level named by the status, so it is carried
        // separately rather than inferred from FIPS140_CERTIFIED_L2.
        Assert.Equal(3UL, report.FipsPhysicalSecurityLevel);
    }

    [Fact]
    public void Deserializes_Certification_Profiles_And_Batch_Certificate()
    {
        const string json = """
        {
            "status": "USER_KEY_REMOTE_COMPROMISE",
            "batchCertificate": "MIIB...",
            "certificationProfiles": [ "consumer", "enterprise" ]
        }
        """;

        var report = JsonSerializer.Deserialize<StatusReport>(json);

        Assert.NotNull(report);
        Assert.Equal("MIIB...", report!.BatchCertificate);
        Assert.Equal(["consumer", "enterprise"], report.CertificationProfiles);
    }

    [Fact]
    public void Optional_Members_Are_Null_When_Absent()
    {
        var report = JsonSerializer.Deserialize<StatusReport>("""{ "status": "FIDO_CERTIFIED_L1" }""");

        Assert.NotNull(report);
        Assert.Null(report!.AuthenticatorVersion);
        Assert.Null(report.BatchCertificate);
        Assert.Null(report.CertificationProfiles);
        Assert.Null(report.SunsetDate);
        Assert.Null(report.FipsRevision);
        Assert.Null(report.FipsPhysicalSecurityLevel);
    }

    [Theory]
    [InlineData("RETIRED", AuthenticatorStatus.RETIRED)]
    [InlineData("FIPS140_CERTIFIED_L1", AuthenticatorStatus.FIPS140_CERTIFIED_L1)]
    [InlineData("FIPS140_CERTIFIED_L2", AuthenticatorStatus.FIPS140_CERTIFIED_L2)]
    [InlineData("FIPS140_CERTIFIED_L3", AuthenticatorStatus.FIPS140_CERTIFIED_L3)]
    [InlineData("FIPS140_CERTIFIED_L4", AuthenticatorStatus.FIPS140_CERTIFIED_L4)]
    public void Parses_Every_Status_Added_Since_The_Enum_Was_Last_Updated(string wireName, AuthenticatorStatus expected)
    {
        var report = JsonSerializer.Deserialize<StatusReport>($$"""{ "status": "{{wireName}}" }""");

        Assert.NotNull(report);
        Assert.Equal(expected, report!.Status);
    }

    /// <summary>
    /// A BLOB payload is parsed as a whole, so a single entry carrying a status the enum does not model takes
    /// the entire payload down with it rather than just that entry. This pins the case that regressed: the
    /// published BLOB contains FIPS-certified and retired authenticators.
    /// </summary>
    [Fact]
    public void Blob_Payload_Parses_When_An_Entry_Carries_A_Fips_Or_Retired_Status()
    {
        const string json = """
        {
            "no": 42,
            "nextUpdate": "2026-10-01",
            "entries": [
                {
                    "aaguid": "0132d110-bf4e-4208-a403-ab4f5f12efe5",
                    "metadataStatement": { "description": "Retired Prototype" },
                    "statusReports": [ { "status": "RETIRED", "effectiveDate": "2025-06-01" } ],
                    "timeOfLastStatusChange": "2025-06-01"
                },
                {
                    "aaguid": "9c835346-796b-4c27-8898-d6032f515cc5",
                    "metadataStatement": { "description": "FIPS Authenticator" },
                    "statusReports": [
                        { "status": "FIDO_CERTIFIED_L2" },
                        { "status": "FIPS140_CERTIFIED_L3", "fipsRevision": 3, "fipsPhysicalSecurityLevel": 2 }
                    ],
                    "timeOfLastStatusChange": "2026-01-05"
                }
            ]
        }
        """;

        // The MDS repositories deserialize the BLOB through the source-generated context rather than the
        // reflection-based serializer, so assert on the path that actually runs in production.
        var payload = JsonSerializer.Deserialize(json, FidoModelSerializerContext.Default.MetadataBLOBPayload);

        Assert.NotNull(payload);
        Assert.Equal(2, payload!.Entries.Length);
        Assert.Equal(AuthenticatorStatus.RETIRED, payload.Entries[0].StatusReports[0].Status);
        Assert.Equal(AuthenticatorStatus.FIPS140_CERTIFIED_L3, payload.Entries[1].StatusReports[1].Status);
        Assert.Equal(2UL, payload.Entries[1].StatusReports[1].FipsPhysicalSecurityLevel);
    }
}
