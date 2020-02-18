using System;
using System.Dynamic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;

namespace Fido2NetLib
{
    /// <summary>
    /// Represents the metadata statement.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#metadata-keys"/>
    /// </remarks>
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
        [JsonProperty("authenticatorVersion")]
        public ushort AuthenticatorVersion { get; set; }

        /// <summary>
        /// Gets or set the FIDO protocol family.
        /// <para>The values "uaf", "u2f", and "fido2" are supported.</para>
        /// </summary>
        [JsonProperty("protocolFamily")]
        public string ProtocolFamily { get; set; }

        //TODO: JsonConvert doesnt seem to behave correctly in this version of .net core. Therefore, we have to two-step the parsing of the version
        [JsonProperty("upv")]
        internal object[] Upv_backing { get; set; }

        /// <summary>
        /// Gets or sets the FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator.
        /// </summary>
        public Version[] Upv
        {
            get
            {
                return Upv_backing?.Select(x =>
                {
                    if (x == null)
                        return (Version)null;
                    var jToken = JValue.Parse(x.ToString());
                    var vString = $"{jToken["major"]}.{jToken["minor"]}";
                    return Version.Parse(vString);
                }).ToArray();
            }

            set { Upv_backing = value?.Select(x => JToken.FromObject(new { major = x.Major, minor = x.Minor })).ToArray(); }
        }

        /// <summary>
        /// Gets or sets the assertion scheme supported by the authenticator.
        /// </summary>
        [JsonProperty("assertionScheme")]
        public string AssertionScheme { get; set; }

        /// <summary>
        /// Gets or sets the preferred authentication algorithm supported by the authenticator.
        /// </summary>
        [JsonProperty("authenticationAlgorithm")]
        public ushort AuthenticationAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the list of authentication algorithms supported by the authenticator.
        /// </summary>
        [JsonProperty("authenticationAlgorithms")]
        public ushort[] AuthenticationAlgorithms { get; set; }

        /// <summary>
        /// Gets or sets the preferred public key format used by the authenticator during registration operations.
        /// </summary>
        [JsonProperty("publicKeyAlgAndEncoding")]
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
        [JsonProperty("attestationTypes")]
        public ushort[] AttestationTypes { get; set; }

        /// <summary>
        /// Gets or sets a list of alternative VerificationMethodANDCombinations.
        /// </summary>
        [JsonProperty("userVerificationDetails")]
        public VerificationMethodDescriptor[][] UserVerificationDetails { get; set; }

        /// <summary>
        /// Gets or sets a 16-bit number representing the bit fields defined by the KEY_PROTECTION constants.
        /// </summary>
        [JsonProperty("keyProtection")]
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
        [JsonProperty("matcherProtection")]
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
        [JsonProperty("attachmentHint")]
        public ulong AttachmentHint { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the authenticator is designed to be used only as a second factor, i.e. requiring some other authentication method as a first factor.
        /// </summary>
        [JsonProperty("isSecondFactorOnly")]
        public bool IsSecondFactorOnly { get; set; }

        /// <summary>
        /// Gets or sets a 16-bit number representing a combination of the bit flags defined by the TRANSACTION_CONFIRMATION_DISPLAY constants.
        /// </summary>
        [JsonProperty("tcDisplay")]
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
        [JsonProperty("attestationRootCertificates")]
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

        /// <summary>
        /// Gets or sets a computed hash value of this <see cref="MetadataStatement"/>.
        /// <para>NOTE: This supports the internal infrastructure of Fido2Net and isn't intented to be used by user code.</para>
        /// </summary>
        public string Hash { get; set; }
    }
}
