using System;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    public interface IMetadataService
    {
        MetadataTOCPayloadEntry GetEntry(Guid aaguid);
        bool ConformanceTesting();
        bool IsInitialized();
        Task Initialize();
    }

    public class MetadataTOCPayloadEntry
    {
        [JsonProperty("aaid")]
        public string Aaid { get; set; }
        [JsonProperty("aaguid")]
        public string AaGuid { get; set; }
        [JsonProperty("attestationCertificateKeyIdentifiers")]
        public string[] AttestationCertificateKeyIdentifiers { get; set; }
        [JsonProperty("hash")]
        public string Hash { get; set; }
        [JsonProperty("url")]
        public string Url { get; set; }
        [JsonProperty("biometricStatusReports")]
        public BiometricStatusReport[] BiometricStatusReports { get; set; }
        [JsonProperty("statusReports", Required = Required.Always)]
        public StatusReport[] StatusReports { get; set; }
        [JsonProperty("timeOfLastStatusChange", Required = Required.Always)]
        public string TimeOfLastStatusChange { get; set; }
        [JsonProperty("rogueListURL")]
        public string RogueListURL { get; set; }
        [JsonProperty("rogueListHash")]
        public string RogueListHash { get; set; }
        [JsonProperty("metadataStatement")]
        [JsonConverter(typeof(Base64UrlConverter))]
        public MetadataStatement MetadataStatement { get; set; }
    }

    public enum AuthenticatorStatus
    {
        NOT_FIDO_CERTIFIED,
        FIDO_CERTIFIED,
        USER_VERIFICATION_BYPASS,
        ATTESTATION_KEY_COMPROMISE,
        USER_KEY_REMOTE_COMPROMISE,
        USER_KEY_PHYSICAL_COMPROMISE,
        UPDATE_AVAILABLE,
        REVOKED,
        SELF_ASSERTION_SUBMITTED,
        FIDO_CERTIFIED_L1,
        FIDO_CERTIFIED_L1plus,
        FIDO_CERTIFIED_L2,
        FIDO_CERTIFIED_L2plus,
        FIDO_CERTIFIED_L3,
        FIDO_CERTIFIED_L3plus
    };

    public class StatusReport
    {
        [JsonProperty("status", Required = Required.Always)]
        public AuthenticatorStatus Status { get; set; }
        [JsonProperty("effectiveDate")]
        public string EffectiveDate { get; set; }
        [JsonProperty("certificate")]
        public string Certificate { get; set; }
        [JsonProperty("url")]
        public string Url { get; set; }
        [JsonProperty("certificationDescriptor")]
        public string CertificationDescriptor { get; set; }
        [JsonProperty("certificateNumber")]
        public string CertificateNumber { get; set; }
        [JsonProperty("certificationPolicyVersion")]
        public string CertificationPolicyVersion { get; set; }
        [JsonProperty("certificationRequirementsVersion")]
        public string CertificationRequirementsVersion { get; set; }
    }
    public class BiometricStatusReport
    {
        [JsonProperty("certLevel", Required = Required.Always)]
        public ushort CertLevel { get; set; }
        [JsonProperty("modality", Required = Required.Always)]
        public ulong Modality { get; set; }
        [JsonProperty("effectiveDate")]
        public string EffectiveDate { get; set; }
        [JsonProperty("certificationDescriptor")]
        public string CertificationDescriptor { get; set; }
        [JsonProperty("certificateNumber")]
        public string CertificateNumber { get; set; }
        [JsonProperty("certificationPolicyVersion")]
        public string CertificationPolicyVersion { get; set; }
        [JsonProperty("certificationRequirementsVersion")]
        public string CertificationRequirementsVersion { get; set; }
    }

    public class MetadataStatement
    {
        [JsonProperty("legalHeader")]
        public string LegalHeader { get; set; }
        [JsonProperty("aaid")]
        public string Aaid { get; set; }
        [JsonProperty("aaguid")]
        public string AaGuid { get; set; }
        [JsonProperty("attestationCertificateKeyIdentifiers")]
        public string[] AttestationCertificateKeyIdentifiers { get; set; }
        [JsonProperty("description", Required = Required.Always)]
        public string Description { get; set; }
        [JsonProperty("alternativeDescriptions")]
        public AlternativeDescriptions IETFLanguageCodesMembers { get; set; }
        [JsonProperty("authenticatorVersion", Required = Required.Always)]
        public ushort AuthenticatorVersion { get; set; }
        [JsonProperty("protocolFamily")]
        public string ProtocolFamily { get; set; }
        [JsonProperty("upv", Required = Required.Always)]
        public Version[] Upv { get; set; }
        [JsonProperty("assertionScheme", Required = Required.Always)]
        public string AssertionScheme { get; set; }
        [JsonProperty("authenticationAlgorithm", Required = Required.Always)]
        public ushort AuthenticationAlgorithm { get; set; }
        [JsonProperty("authenticationAlgorithms")]
        public ushort[] AuthenticationAlgorithms { get; set; }
        [JsonProperty("publicKeyAlgAndEncoding", Required = Required.Always)]
        public ushort PublicKeyAlgAndEncoding { get; set; }
        [JsonProperty("publicKeyAlgAndEncodings")]
        public ushort[] PublicKeyAlgAndEncodings { get; set; }
        [JsonProperty("attestationTypes", Required = Required.Always)]
        public ushort[] AttestationTypes { get; set; }
        [JsonProperty("userVerificationDetails", Required = Required.Always)]
        public VerificationMethodDescriptor[][] UserVerificationDetails { get; set; }
        [JsonProperty("keyProtection", Required = Required.Always)]
        public ushort KeyProtection { get; set; }
        [JsonProperty("isKeyRestricted")]
        public bool IsKeyRestricted { get; set; }
        [JsonProperty("isFreshUserVerificationRequired")]
        public bool IsFreshUserVerificationRequired { get; set; }
        [JsonProperty("matcherProtection", Required = Required.Always)]
        public ushort MatcherProtection { get; set; }
        [JsonProperty("cryptoStrength")]
        public ushort CryptoStrength { get; set; }
        [JsonProperty("operatingEnv")]
        public string OperatingEnv { get; set; }
        [JsonProperty("attachmentHint", Required = Required.Always)]
        public ulong AttachmentHint { get; set; }
        [JsonProperty("isSecondFactorOnly", Required = Required.Always)]
        public bool IsSecondFactorOnly { get; set; }
        [JsonProperty("tcDisplay", Required = Required.Always)]
        public ushort TcDisplay { get; set; }
        [JsonProperty("tcDisplayContentType")]
        public string TcDisplayContentType { get; set; }
        [JsonProperty("tcDisplayPNGCharacteristics")]
        public DisplayPNGCharacteristicsDescriptor[] TcDisplayPNGCharacteristics { get; set; }
        [JsonProperty("attestationRootCertificates", Required = Required.Always)]
        public string[] AttestationRootCertificates { get; set; }
        [JsonProperty("ecdaaTrustAnchors")]
        public EcdaaTrustAnchor[] EcdaaTrustAnchors { get; set; }
        [JsonProperty("icon")]
        public string Icon { get; set; }
        [JsonProperty("supportedExtensions")]
        public ExtensionDescriptor[] SupportedExtensions { get; set; }
        public string Hash { get; set; }
    }

    public class BiometricAccuracyDescriptor
    {
        [JsonProperty("selfAttestedFRR ")]
        public double SelfAttestedFRR { get; set; }
        [JsonProperty("selfAttestedFAR ")]
        public double SelfAttestedFAR { get; set; }
        [JsonProperty("maxTemplates")]
        public ushort MaxTemplates { get; set; }
        [JsonProperty("maxRetries")]
        public ushort MaxRetries { get; set; }
        [JsonProperty("blockSlowdown")]
        public ushort BlockSlowdown { get; set; }
    }
    public class PatternAccuracyDescriptor
    {
        [JsonProperty("minComplexity", Required = Required.Always)]
        public ulong MinComplexity { get; set; }
        [JsonProperty("maxRetries")]
        public ushort MaxRetries { get; set; }
        [JsonProperty("blockSlowdown")]
        public ushort BlockSlowdown { get; set; }
    }

    public class CodeAccuracyDescriptor
    {
        [JsonProperty("base", Required = Required.Always)]
        public ushort Base { get; set; }
        [JsonProperty("minLength", Required = Required.Always)]
        public ushort MinLength { get; set; }
        [JsonProperty("maxRetries")]
        public ushort MaxRetries { get; set; }
        [JsonProperty("blockSlowdown")]
        public ushort BlockSlowdown { get; set; }
    }

    public class VerificationMethodDescriptor
    {
        [JsonProperty("userVerification", Required = Required.Always)]
        public ulong UserVerification { get; set; }
        [JsonProperty("caDesc")]
        public CodeAccuracyDescriptor CaDesc { get; set; }
        [JsonProperty("baDesc")]
        public BiometricAccuracyDescriptor BaDesc { get; set; }
        [JsonProperty("paDesc")]
        public PatternAccuracyDescriptor PaDesc { get; set; }
    }
    public class EcdaaTrustAnchor
    {
        [JsonProperty("x", Required = Required.Always)]
        public string X { get; set; }
        [JsonProperty("y", Required = Required.Always)]
        public string Y { get; set; }
        [JsonProperty("c", Required = Required.Always)]
        public string C { get; set; }
        [JsonProperty("sx", Required = Required.Always)]
        public string SX { get; set; }
        [JsonProperty("sy", Required = Required.Always)]
        public string SY { get; set; }
        [JsonProperty("G1Curve", Required = Required.Always)]
        public string G1Curve { get; set; }
    }

    public class AlternativeDescriptions
    {
        [JsonProperty("alternativeDescriptions")]
        public System.Collections.Generic.Dictionary<string, string> IETFLanguageCodesMembers { get; set; }
    }

    public class DisplayPNGCharacteristicsDescriptor
    {
        [JsonProperty("width", Required = Required.Always)]
        public ulong Width { get; set; }
        [JsonProperty("height", Required = Required.Always)]
        public ulong Height { get; set; }
        [JsonProperty("bitDepth", Required = Required.Always)]
        public byte BitDepth { get; set; }
        [JsonProperty("colorType", Required = Required.Always)]
        public byte ColorType { get; set; }
        [JsonProperty("compression", Required = Required.Always)]
        public byte Compression { get; set; }
        [JsonProperty("filter", Required = Required.Always)]
        public byte Filter { get; set; }
        [JsonProperty("interlace", Required = Required.Always)]
        public byte Interlace { get; set; }
        [JsonProperty("plte")]
        public rgbPaletteEntry[] Plte { get; set; }
    }

    public class ExtensionDescriptor
    {
        [JsonProperty("id", Required = Required.Always)]
        public string Id { get; set; }
        [JsonProperty("tag")]
        public ushort Tag { get; set; }
        [JsonProperty("data")]
        public string Data { get; set; }
        [JsonProperty("fail_if_unknown", Required = Required.Always)]
        public bool Fail_If_Unknown { get; set; }
    }

    public class rgbPaletteEntry
    {
        [JsonProperty("r", Required = Required.Always)]
        public ushort R { get; set; }
        [JsonProperty("g", Required = Required.Always)]
        public ushort G { get; set; }
        [JsonProperty("b", Required = Required.Always)]
        public ushort B { get; set; }
    }
}
