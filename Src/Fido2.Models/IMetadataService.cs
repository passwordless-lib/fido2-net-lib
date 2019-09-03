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

    /// <summary>
    /// Represents the metadata TOC payload data strucutre.
    /// </summary>
    public class MetadataTOCPayloadEntry
    {
        /// <summary>
        /// Gets or sets the AAID.
        /// <para>The AAID of the authenticator this metadata TOC payload entry relates to.</para>
        /// </summary>
        [JsonProperty("aaid")]
        public string Aaid { get; set; }
        /// <summary>
        /// Gets or sets the AAGUID.
        /// <para>The Authenticator Attestation GUID.</para>
        /// </summary>
        [JsonProperty("aaguid")]
        public string AaGuid { get; set; }
        /// <summary>
        /// Gets or sets a list of the attestation certificate public key identifiers encoded as hex string.
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        ///     <item>The hex string must not contain any non-hex characters (e.g. spaces).</item>
        ///     <item>All hex letters must be lower case.</item>
        ///     <item>This field must be set if neither aaid nor aaguid are set.</item>
        ///     <item>Setting this field implies that the attestation certificate(s) are dedicated to a single authenticator model.</item>
        /// </list>
        /// <para>FIDO U2F authenticators do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.</para>
        /// </remarks>
        [JsonProperty("attestationCertificateKeyIdentifiers")]
        public string[] AttestationCertificateKeyIdentifiers { get; set; }
        /// <summary>
        /// Gets or sets the hash value computed over the base64url encoding of the UTF-8 representation of the JSON encoded metadata statement available at url.
        /// </summary>
        /// <remarks>
        /// The hash algorithm related to the signature algorithm specified in the JWTHeader (see Metadata TOC) must be used.
        /// <para>This method of base64url encoding the UTF-8 representation is also used by JWT [JWT] to avoid encoding ambiguities.</para>
        /// </remarks>
        [JsonProperty("hash")]
        public string Hash { get; set; }
        /// <summary>
        /// Gets or sets the Uniform resource locator (URL) of the encoded metadata statement for this authenticator model (identified by its AAID, AAGUID or attestationCertificateKeyIdentifier).
        /// </summary>
        /// <remarks>
        /// This URL must point to the base64url encoding of the UTF-8 representation of the JSON encoded metadata statement.
        /// <para>If this field is missing, the metadata statement has not been published.</para>
        /// </remarks>
        [JsonProperty("url")]
        public string Url { get; set; }
        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("biometricStatusReports")]
        public BiometricStatusReport[] BiometricStatusReports { get; set; }
        /// <summary>
        /// Gets or sets an array of status reports applicable to this authenticator.
        /// </summary>
        [JsonProperty("statusReports", Required = Required.Always)]
        public StatusReport[] StatusReports { get; set; }
        /// <summary>
        /// Gets or sets ISO-8601 formatted date since when the status report array was set to the current value. 
        /// </summary>
        [JsonProperty("timeOfLastStatusChange", Required = Required.Always)]
        public string TimeOfLastStatusChange { get; set; }
        /// <summary>
        /// Gets or sets an URL of a list of rogue (i.e. untrusted) individual authenticators. 
        /// </summary>
        [JsonProperty("rogueListURL")]
        public string RogueListURL { get; set; }
        /// <summary>
        /// Gets or sets the hash value computed of <see cref="RogueListURL"/>.
        /// </summary>
        /// <remarks>
        /// This hash value must be present and non-empty whenever rogueListURL is present.
        /// </remarks>
        [JsonProperty("rogueListHash")]
        public string RogueListHash { get; set; }
        /// <summary>
        /// Gets or sets the metadata statement.
        /// </summary>
        [JsonProperty("metadataStatement")]
        [JsonConverter(typeof(Base64UrlConverter))]
        public MetadataStatement MetadataStatement { get; set; }
    }

    /// <summary>
    /// Describes the status of an authenticator model as identified by its AAID and potentially some additional information (such as a specific attestation key). 
    /// </summary>
    public enum AuthenticatorStatus
    {
        /// <summary>
        /// This authenticator is not FIDO certified. 
        /// </summary>
        NOT_FIDO_CERTIFIED,
        /// <summary>
        /// This authenticator has passed FIDO functional certification. This certification scheme is phased out and will be replaced by FIDO_CERTIFIED_L1.
        /// </summary>
        FIDO_CERTIFIED,
        /// <summary>
        /// Indicates that malware is able to bypass the user verification. 
        /// <para>This means that the authenticator could be used without the user's consent and potentially even without the user's knowledge.</para>
        /// </summary>
        USER_VERIFICATION_BYPASS,
        /// <summary>
        /// Indicates that an attestation key for this authenticator is known to be compromised. Additional data should be supplied, including the key identifier and the date of compromise, if known.
        /// </summary>
        ATTESTATION_KEY_COMPROMISE,
        /// <summary>
        /// This authenticator has identified weaknesses that allow registered keys to be compromised and should not be trusted. 
        /// <para>This would include both, e.g. weak entropy that causes predictable keys to be generated or side channels that allow keys or signatures to be forged, guessed or extracted.</para>
        /// </summary>
        USER_KEY_REMOTE_COMPROMISE,
        /// <summary>
        /// This authenticator has known weaknesses in its key protection mechanism(s) that allow user keys to be extracted by an adversary in physical possession of the device.
        /// </summary>
        USER_KEY_PHYSICAL_COMPROMISE,
        /// <summary>
        /// A software or firmware update is available for the device.
        /// </summary>
        UPDATE_AVAILABLE,
        /// <summary>
        /// The FIDO Alliance has determined that this authenticator should not be trusted.
        /// </summary>
        REVOKED,
        /// <summary>
        /// The authenticator vendor has completed and submitted the self-certification checklist to the FIDO Alliance. 
        /// </summary>
        /// <remarks>
        /// If this completed checklist is publicly available, the URL will be specified in <see cref="StatusReport.Url"/>. 
        /// </remarks>
        SELF_ASSERTION_SUBMITTED,
        /// <summary>
        /// The authenticator has passed FIDO Authenticator certification at level 1. This level is the more strict successor of FIDO_CERTIFIED.
        /// </summary>
        FIDO_CERTIFIED_L1,
        FIDO_CERTIFIED_L1plus,
        /// <summary>
        /// The authenticator has passed FIDO Authenticator certification at level 2. This level is more strict than level 1. 
        /// </summary>
        FIDO_CERTIFIED_L2,
        FIDO_CERTIFIED_L2plus,
        /// <summary>
        /// The authenticator has passed FIDO Authenticator certification at level 3. This level is more strict than level 2.
        /// </summary>
        FIDO_CERTIFIED_L3,
        FIDO_CERTIFIED_L3plus
    };

    public class StatusReport
    {
        /// <summary>
        /// Gets or sets the status of the authenticator.
        /// <para>Additional fields may be set depending on this value.</para>
        /// </summary>
        [JsonProperty("status", Required = Required.Always)]
        public AuthenticatorStatus Status { get; set; }
        /// <summary>
        /// Gets or set the ISO-8601 formatted date since when the status code was set, if applicable.
        /// <para>If no date is given, the status is assumed to be effective while present.</para>
        /// </summary>
        [JsonProperty("effectiveDate")]
        public string EffectiveDate { get; set; }
        /// <summary>
        /// Gets or sets Base64-encoded PKIX certificate value related to the current status, if applicable.
        /// </summary>
        /// <remarks>
        /// Base64-encoded [RFC4648] (not base64url!) / DER [ITU-X690-2008] PKIX certificate.
        /// </remarks>
        [JsonProperty("certificate")]
        public string Certificate { get; set; }
        /// <summary>
        /// Gets or sets the HTTPS URL where additional information may be found related to the current status, if applicable.
        /// </summary>
        /// <remarks>
        /// For example a link to a web page describing an available firmware update in the case of status UPDATE_AVAILABLE, or a link to a description of an identified issue in the case of status USER_VERIFICATION_BYPASS.
        /// </remarks>
        [JsonProperty("url")]
        public string Url { get; set; }
        /// <summary>
        /// Gets or sets a description of the externally visible aspects of the Authenticator Certification evaluation. 
        /// </summary>
        [JsonProperty("certificationDescriptor")]
        public string CertificationDescriptor { get; set; }
        /// <summary>
        /// Gets or sets the unique identifier for the issued Certification.
        /// </summary>
        [JsonProperty("certificateNumber")]
        public string CertificateNumber { get; set; }
        /// <summary>
        /// Gets or set the version of the Authenticator Certification Policy the implementation is Certified to. 
        /// </summary>
        [JsonProperty("certificationPolicyVersion")]
        public string CertificationPolicyVersion { get; set; }
        /// <summary>
        /// Gets or set the version of the Authenticator Security Requirements the implementation is Certified to.
        /// </summary>
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
        /// <summary>
        /// Gets or sets the legalHeader, if present, contains a legal guide for accessing and using metadata, which itself MAY contain URL(s) pointing to further information, such as a full Terms and Conditions statement. 
        /// </summary>
        [JsonProperty("legalHeader")]
        public string LegalHeader { get; set; }
        /// <summary>
        /// Gets or set the Authenticator Attestation ID.
        /// </summary>
        /// <remarks>
        /// Note: FIDO UAF Authenticators support AAID, but they don't support AAGUID.
        /// </remarks>
        [JsonProperty("aaid")]
        public string Aaid { get; set; }
        /// <summary>
        /// Gets or sets the Authenticator Attestation GUID. 
        /// </summary>
        /// <remarks>
        /// This field MUST be set if the authenticator implements FIDO 2. 
        /// <para>Note: FIDO 2 Authenticators support AAGUID, but they don't support AAID.</para>
        /// </remarks>
        [JsonProperty("aaguid")]
        public string AaGuid { get; set; }
        /// <summary>
        /// Gets or sets a list of the attestation certificate public key identifiers encoded as hex string.
        /// </summary>
        [JsonProperty("attestationCertificateKeyIdentifiers")]
        public string[] AttestationCertificateKeyIdentifiers { get; set; }
        /// <summary>
        /// Gets or sets a human-readable, short description of the authenticator, in English. 
        /// </summary>
        [JsonProperty("description", Required = Required.Always)]
        public string Description { get; set; }
        /// <summary>
        /// Gets or set a list of human-readable short descriptions of the authenticator in different languages.
        /// </summary>
        [JsonProperty("alternativeDescriptions")]
        public AlternativeDescriptions IETFLanguageCodesMembers { get; set; }
        /// <summary>
        /// Gets or set earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified in this metadata statement. 
        /// </summary>
        [JsonProperty("authenticatorVersion", Required = Required.Always)]
        public ushort AuthenticatorVersion { get; set; }
        /// <summary>
        /// Gets or set the FIDO protocol family.
        /// <para>The values "uaf", "u2f", and "fido2" are supported.</para>
        /// </summary>
        [JsonProperty("protocolFamily")]
        public string ProtocolFamily { get; set; }
        /// <summary>
        /// Gets or sets the FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator.
        /// </summary>
        [JsonProperty("upv", Required = Required.Always)]
        public Version[] Upv { get; set; }
        /// <summary>
        /// Gets or sets the assertion scheme supported by the authenticator.
        /// </summary>
        [JsonProperty("assertionScheme", Required = Required.Always)]
        public string AssertionScheme { get; set; }
        /// <summary>
        /// Gets or sets the preferred authentication algorithm supported by the authenticator.
        /// </summary>
        [JsonProperty("authenticationAlgorithm", Required = Required.Always)]
        public ushort AuthenticationAlgorithm { get; set; }
        /// <summary>
        /// Gets or sets the list of authentication algorithms supported by the authenticator. 
        /// </summary>
        [JsonProperty("authenticationAlgorithms")]
        public ushort[] AuthenticationAlgorithms { get; set; }
        /// <summary>
        /// Gets or sets the preferred public key format used by the authenticator during registration operations.
        /// </summary>
        [JsonProperty("publicKeyAlgAndEncoding", Required = Required.Always)]
        public ushort PublicKeyAlgAndEncoding { get; set; }
        /// <summary>
        /// Gets or sets the list of public key formats supported by the authenticator during registration operations.
        /// </summary>
        [JsonProperty("publicKeyAlgAndEncodings")]
        public ushort[] PublicKeyAlgAndEncodings { get; set; }
        /// <summary>
        /// Gets or sets the supported attestation type(s).
        /// </summary>
        /// <remarks>
        /// For example: TAG_ATTESTATION_BASIC_FULL(0x3E07), TAG_ATTESTATION_BASIC_SURROGATE(0x3E08). 
        /// </remarks>
        [JsonProperty("attestationTypes", Required = Required.Always)]
        public ushort[] AttestationTypes { get; set; }
        /// <summary>
        /// Gets or sets a list of alternative VerificationMethodANDCombinations.
        /// </summary>
        [JsonProperty("userVerificationDetails", Required = Required.Always)]
        public VerificationMethodDescriptor[][] UserVerificationDetails { get; set; }
        /// <summary>
        /// Gets or sets a 16-bit number representing the bit fields defined by the KEY_PROTECTION constants.
        /// </summary>
        [JsonProperty("keyProtection", Required = Required.Always)]
        public ushort KeyProtection { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether the Uauth private key is restricted by the authenticator to only sign valid FIDO signature assertions.
        /// </summary>
        /// <remarks>
        /// <list type="bullet">
        ///     <item>This entry is set to true, if the Uauth private key is restricted by the authenticator to only sign valid FIDO signature assertions.</item>
        ///     <item>This entry is set to false, if the authenticator doesn't restrict the Uauth key to only sign valid FIDO signature assertions. In this case, the calling application could potentially get any hash value signed by the authenticator.</item>
        ///     <item>If this field is missing, the assumed value is isKeyRestricted=true.</item>
        /// </list>
        /// </remarks>
        [JsonProperty("isKeyRestricted")]
        public bool IsKeyRestricted { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether the Uauth key usage always requires a fresh user verification.
        /// </summary>
        [JsonProperty("isFreshUserVerificationRequired")]
        public bool IsFreshUserVerificationRequired { get; set; }
        /// <summary>
        /// Gets or sets a 16-bit number representing the bit fields defined by the MATCHER_PROTECTION constants.
        /// </summary>
        [JsonProperty("matcherProtection", Required = Required.Always)]
        public ushort MatcherProtection { get; set; }
        /// <summary>
        /// Gets or sets the authenticator's overall claimed cryptographic strength in bits (sometimes also called security strength or security level).
        /// </summary>
        /// <remarks>If this value is absent, the cryptographic strength is unknown.</remarks>
        [JsonProperty("cryptoStrength")]
        public ushort CryptoStrength { get; set; }
        /// <summary>
        /// Gets or sets a description of the particular operating environment that is used for the Authenticator.
        /// </summary>
        [JsonProperty("operatingEnv")]
        public string OperatingEnv { get; set; }
        /// <summary>
        /// Gets or sets a 32-bit number representing the bit fields defined by the ATTACHMENT_HINT constants.
        /// </summary>
        [JsonProperty("attachmentHint", Required = Required.Always)]
        public ulong AttachmentHint { get; set; }
        /// <summary>
        /// Gets or sets a value indicating whether the authenticator is designed to be used only as a second factor, i.e. requiring some other authentication method as a first factor.
        /// </summary>
        [JsonProperty("isSecondFactorOnly", Required = Required.Always)]
        public bool IsSecondFactorOnly { get; set; }
        /// <summary>
        /// Gets or sets a 16-bit number representing a combination of the bit flags defined by the TRANSACTION_CONFIRMATION_DISPLAY constants.
        /// </summary>
        [JsonProperty("tcDisplay", Required = Required.Always)]
        public ushort TcDisplay { get; set; }
        /// <summary>
        /// Gets or sets the supported MIME content type [RFC2049] for the transaction confirmation display, such as text/plain or image/png. 
        /// </summary>
        [JsonProperty("tcDisplayContentType")]
        public string TcDisplayContentType { get; set; }
        /// <summary>
        /// Gets or sets a list of alternative DisplayPNGCharacteristicsDescriptor.
        /// </summary>
        [JsonProperty("tcDisplayPNGCharacteristics")]
        public DisplayPNGCharacteristicsDescriptor[] TcDisplayPNGCharacteristics { get; set; }
        /// <summary>
        /// Gets or sets a list of a PKIX [RFC5280] X.509 certificate that is a valid trust anchor for this authenticator model.
        /// </summary>
        [JsonProperty("attestationRootCertificates", Required = Required.Always)]
        public string[] AttestationRootCertificates { get; set; }
        /// <summary>
        /// Gets or set a list of trust anchors used for ECDAA attestation. 
        /// </summary>
        [JsonProperty("ecdaaTrustAnchors")]
        public EcdaaTrustAnchor[] EcdaaTrustAnchors { get; set; }
        /// <summary>
        /// Gets or set a data: url [RFC2397] encoded PNG [PNG] icon for the Authenticator.
        /// </summary>
        [JsonProperty("icon")]
        public string Icon { get; set; }
        /// <summary>
        /// Gets or sets a list of extensions supported by the authenticator. 
        /// </summary>
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
