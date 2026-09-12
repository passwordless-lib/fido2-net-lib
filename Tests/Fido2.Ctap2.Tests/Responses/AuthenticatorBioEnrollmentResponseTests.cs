namespace Fido2NetLib.Ctap2.Tests;

public class AuthenticatorBioEnrollmentResponseTests
{
    [Fact]
    public void DeserializeEnrollmentProgress()
    {
        // Shape returned by enrollBegin/enrollCaptureNextSample: an in-progress enrollment's template ID,
        // the status of the last sample, and how many samples are still needed.
        string hexEncodedCborData = """

            00                                      # status = success
            a3                                      # map(3)
               04                                   # unsigned(4) - templateId
               43                                   # bytes(3)
                  010203                            # ...
               05                                   # unsigned(5) - lastEnrollSampleStatus
               01                                   # unsigned(1)
               06                                   # unsigned(6) - remainingSamples
               05                                   # unsigned(5)
            """;

        var response = AuthenticatorBioEnrollmentResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.Equal("010203", Convert.ToHexString(response.TemplateId!).ToLower());
        Assert.Equal(1, response.LastEnrollSampleStatus);
        Assert.Equal(5, response.RemainingSamples);
        Assert.Null(response.Modality);
        Assert.Null(response.TemplateInfos);
    }

    [Fact]
    public void DeserializeSensorInfo()
    {
        // Shape returned by getFingerprintSensorInfo.
        string hexEncodedCborData = """

            00                                      # status = success
            a4                                      # map(4)
               01                                   # unsigned(1) - modality
               01                                   # unsigned(1) - Fingerprint
               02                                   # unsigned(2) - fingerprintKind
               01                                   # unsigned(1) - touch type
               03                                   # unsigned(3) - maxCaptureSamplesRequiredForEnroll
               05                                   # unsigned(5)
               08                                   # unsigned(8) - maxTemplateFriendlyName
               18 20                                # unsigned(32)
            """;

        var response = AuthenticatorBioEnrollmentResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.Equal(AuthenticatorBioEnrollmentModality.Fingerprint, response.Modality);
        Assert.Equal(1, response.FingerprintKind);
        Assert.Equal(5, response.MaxCaptureSamplesRequiredForEnroll);
        Assert.Equal(32, response.MaxTemplateFriendlyName);
    }

    [Fact]
    public void DeserializeEnumeratedTemplates()
    {
        // Shape returned by enumerateEnrollments: a templateInfos array, one entry with a friendly name and
        // one without -- templateFriendlyName is optional per entry.
        string hexEncodedCborData = """

            00                                      # status = success
            a1                                      # map(1)
               07                                   # unsigned(7) - templateInfos
               82                                   # array(2)
                  a2                                # map(2) - entry 1
                     01                              # unsigned(1) - templateId
                     42                              # bytes(2)
                        aabb                        # ...
                     02                              # unsigned(2) - templateFriendlyName
                     64                              # text(4)
                        4c656674                     # "Left"
                  a1                                # map(1) - entry 2, no friendly name
                     01                              # unsigned(1) - templateId
                     42                              # bytes(2)
                        ccdd                        # ...
            """;

        var response = AuthenticatorBioEnrollmentResponse.FromCborObject(TestHelper.GetResponse(hexEncodedCborData).GetCborObject());

        Assert.NotNull(response.TemplateInfos);
        Assert.Equal(2, response.TemplateInfos!.Length);

        Assert.Equal("aabb", Convert.ToHexString(response.TemplateInfos[0].TemplateId).ToLower());
        Assert.Equal("Left", response.TemplateInfos[0].TemplateFriendlyName);

        Assert.Equal("ccdd", Convert.ToHexString(response.TemplateInfos[1].TemplateId).ToLower());
        Assert.Null(response.TemplateInfos[1].TemplateFriendlyName);
    }
}
