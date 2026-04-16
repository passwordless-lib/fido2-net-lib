using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Fido2NetLib;
using Fido2NetLib.Objects;

namespace Test.Converters;

public class EnumSerializationTests
{
    private static void TestEnum<TEnum>(TEnum value, string expectedString) where TEnum : struct, Enum
    {
        // System.Text.Json
        var stjSerialized = System.Text.Json.JsonSerializer.Serialize(value);
        Assert.Equal($"\"{expectedString}\"", stjSerialized);
        var stjDeserialized = System.Text.Json.JsonSerializer.Deserialize<TEnum>(stjSerialized);
        Assert.Equal(value, stjDeserialized);

        // Newtonsoft.Json
        var settings = new JsonSerializerSettings();
        settings.Converters.Add(new StringEnumConverter());
        var newtonsoftSerialized = JsonConvert.SerializeObject(value, new StringEnumConverter());
        Assert.Equal($"\"{expectedString}\"", newtonsoftSerialized);
        var newtonsoftDeserialized = JsonConvert.DeserializeObject<TEnum>(newtonsoftSerialized, new StringEnumConverter());
        Assert.Equal(value, newtonsoftDeserialized);
    }

    [Theory]
    [InlineData(PublicKeyCredentialType.PublicKey, "public-key")]
    [InlineData(PublicKeyCredentialType.Invalid, "invalid")]
    public void TestPublicKeyCredentialType(PublicKeyCredentialType value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(UserVerificationMethods.PRESENCE_INTERNAL, "presence_internal")]
    [InlineData(UserVerificationMethods.FINGERPRINT_INTERNAL, "fingerprint_internal")]
    [InlineData(UserVerificationMethods.PASSCODE_INTERNAL, "passcode_internal")]
    [InlineData(UserVerificationMethods.VOICEPRINT_INTERNAL, "voiceprint_internal")]
    [InlineData(UserVerificationMethods.FACEPRINT_INTERNAL, "faceprint_internal")]
    [InlineData(UserVerificationMethods.LOCATION_INTERNAL, "location_internal")]
    [InlineData(UserVerificationMethods.EYEPRINT_INTERNAL, "eyeprint_internal")]
    [InlineData(UserVerificationMethods.PATTERN_INTERNAL, "pattern_internal")]
    [InlineData(UserVerificationMethods.HANDPRINT_INTERNAL, "handprint_internal")]
    [InlineData(UserVerificationMethods.PASSCODE_EXTERNAL, "passcode_external")]
    [InlineData(UserVerificationMethods.PATTERN_EXTERNAL, "pattern_external")]
    [InlineData(UserVerificationMethods.NONE, "none")]
    [InlineData(UserVerificationMethods.ALL, "all")]
    public void TestUserVerificationMethods(UserVerificationMethods value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(AttestationStatementFormatIdentifier.Packed, "packed")]
    [InlineData(AttestationStatementFormatIdentifier.Tpm, "tpm")]
    [InlineData(AttestationStatementFormatIdentifier.AndroidKey, "android-key")]
    [InlineData(AttestationStatementFormatIdentifier.AndroidSafetyNet, "android-safetynet")]
    [InlineData(AttestationStatementFormatIdentifier.FidoU2f, "fido-u2f")]
    [InlineData(AttestationStatementFormatIdentifier.Apple, "apple")]
    [InlineData(AttestationStatementFormatIdentifier.None, "none")]
    public void TestAttestationStatementFormatIdentifier(AttestationStatementFormatIdentifier value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(AuthenticatorTransport.Usb, "usb")]
    [InlineData(AuthenticatorTransport.Nfc, "nfc")]
    [InlineData(AuthenticatorTransport.Ble, "ble")]
    [InlineData(AuthenticatorTransport.SmartCard, "smart-card")]
    [InlineData(AuthenticatorTransport.Hybrid, "hybrid")]
    [InlineData(AuthenticatorTransport.Internal, "internal")]
    public void TestAuthenticatorTransport(AuthenticatorTransport value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(KeyProtection.SOFTWARE, "software")]
    [InlineData(KeyProtection.HARDWARE, "hardware")]
    [InlineData(KeyProtection.TEE, "tee")]
    [InlineData(KeyProtection.SECURE_ELEMENT, "secure_element")]
    [InlineData(KeyProtection.REMOTE_HANDLE, "remote_handle")]
    public void TestKeyProtection(KeyProtection value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(AttestationConveyancePreference.None, "none")]
    [InlineData(AttestationConveyancePreference.Indirect, "indirect")]
    [InlineData(AttestationConveyancePreference.Direct, "direct")]
    [InlineData(AttestationConveyancePreference.Enterprise, "enterprise")]
    public void TestAttestationConveyancePreference(AttestationConveyancePreference value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(CredentialProtectionPolicy.UserVerificationOptional, "userVerificationOptional")]
    [InlineData(CredentialProtectionPolicy.UserVerificationOptionalWithCredentialIdList, "userVerificationOptionalWithCredentialIDList")]
    [InlineData(CredentialProtectionPolicy.UserVerificationRequired, "userVerificationRequired")]
    public void TestCredentialProtectionPolicy(CredentialProtectionPolicy value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(PublicKeyCredentialHint.SecurityKey, "security-key")]
    [InlineData(PublicKeyCredentialHint.ClientDevice, "client-device")]
    [InlineData(PublicKeyCredentialHint.Hybrid, "hybrid")]
    public void TestPublicKeyCredentialHint(PublicKeyCredentialHint value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(ResidentKeyRequirement.Required, "required")]
    [InlineData(ResidentKeyRequirement.Preferred, "preferred")]
    [InlineData(ResidentKeyRequirement.Discouraged, "discouraged")]
    public void TestResidentKeyRequirement(ResidentKeyRequirement value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(UserVerificationRequirement.Required, "required")]
    [InlineData(UserVerificationRequirement.Preferred, "preferred")]
    [InlineData(UserVerificationRequirement.Discouraged, "discouraged")]
    public void TestUserVerificationRequirement(UserVerificationRequirement value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(AuthenticatorAttachment.Platform, "platform")]
    [InlineData(AuthenticatorAttachment.CrossPlatform, "cross-platform")]
    public void TestAuthenticatorAttachment(AuthenticatorAttachment value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(LargeBlobSupport.Required, "required")]
    [InlineData(LargeBlobSupport.Preferred, "preferred")]
    public void TestLargeBlobSupport(LargeBlobSupport value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(Fido2Configuration.CredentialBackupPolicy.Required, "required")]
    [InlineData(Fido2Configuration.CredentialBackupPolicy.Allowed, "allowed")]
    [InlineData(Fido2Configuration.CredentialBackupPolicy.Disallowed, "disallowed")]
    public void TestCredentialBackupPolicy(Fido2Configuration.CredentialBackupPolicy value, string expected) => TestEnum(value, expected);

    [Theory]
    [InlineData(AuthenticatorStatus.NOT_FIDO_CERTIFIED, "NOT_FIDO_CERTIFIED")]
    [InlineData(AuthenticatorStatus.FIDO_CERTIFIED, "FIDO_CERTIFIED")]
    [InlineData(AuthenticatorStatus.USER_VERIFICATION_BYPASS, "USER_VERIFICATION_BYPASS")]
    [InlineData(AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE, "ATTESTATION_KEY_COMPROMISE")]
    [InlineData(AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE, "USER_KEY_REMOTE_COMPROMISE")]
    [InlineData(AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE, "USER_KEY_PHYSICAL_COMPROMISE")]
    [InlineData(AuthenticatorStatus.UPDATE_AVAILABLE, "UPDATE_AVAILABLE")]
    [InlineData(AuthenticatorStatus.REVOKED, "REVOKED")]
    [InlineData(AuthenticatorStatus.SELF_ASSERTION_SUBMITTED, "SELF_ASSERTION_SUBMITTED")]
    [InlineData(AuthenticatorStatus.FIDO_CERTIFIED_L1, "FIDO_CERTIFIED_L1")]
    [InlineData(AuthenticatorStatus.FIDO_CERTIFIED_L1plus, "FIDO_CERTIFIED_L1plus")]
    [InlineData(AuthenticatorStatus.FIDO_CERTIFIED_L2, "FIDO_CERTIFIED_L2")]
    [InlineData(AuthenticatorStatus.FIDO_CERTIFIED_L2plus, "FIDO_CERTIFIED_L2plus")]
    [InlineData(AuthenticatorStatus.FIDO_CERTIFIED_L3, "FIDO_CERTIFIED_L3")]
    [InlineData(AuthenticatorStatus.FIDO_CERTIFIED_L3plus, "FIDO_CERTIFIED_L3plus")]
    public void TestAuthenticatorStatus(AuthenticatorStatus value, string expected) => TestEnum(value, expected);
    
    [Theory]
    [InlineData(COSE.Algorithm.ES256, "-7")]
    [InlineData(COSE.Algorithm.RS256, "-257")]
    public void TestCOSEAlgorithm(COSE.Algorithm value, string expected)
    {
        // COSE algorithms are currently serialized as numbers in STJ
        var stjSerialized = System.Text.Json.JsonSerializer.Serialize(value);
        Assert.Equal(expected, stjSerialized);
        var stjDeserialized = System.Text.Json.JsonSerializer.Deserialize<COSE.Algorithm>(stjSerialized);
        Assert.Equal(value, stjDeserialized);

        // Newtonsoft.Json (with StringEnumConverter) serializes them as strings if we use the converter, 
        // but since they don't have [EnumMember], it uses the member name.
        var newtonsoftSerialized = JsonConvert.SerializeObject(value, new StringEnumConverter());
        Assert.Equal($"\"{(value.ToString())}\"", newtonsoftSerialized);
    }

    [Theory]
    [InlineData(COSE.EllipticCurve.P256, "1")]
    [InlineData(COSE.EllipticCurve.Ed25519, "6")]
    public void TestCOSEEllipticCurve(COSE.EllipticCurve value, string expected)
    {
        var stjSerialized = System.Text.Json.JsonSerializer.Serialize(value);
        Assert.Equal(expected, stjSerialized);
        var stjDeserialized = System.Text.Json.JsonSerializer.Deserialize<COSE.EllipticCurve>(stjSerialized);
        Assert.Equal(value, stjDeserialized);

        var newtonsoftSerialized = JsonConvert.SerializeObject(value, new StringEnumConverter());
        Assert.Equal($"\"{(value.ToString())}\"", newtonsoftSerialized);
    }
}
