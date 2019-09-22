using System;
using Newtonsoft.Json;

namespace Fido2NetLib
{
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
        [JsonProperty("authenticatorVersion")]
        public ushort AuthenticatorVersion { get; set; }
        [JsonProperty("protocolFamily")]
        public string ProtocolFamily { get; set; }
        [JsonProperty("upv")]
        public Version[] Upv { get; set; }
        [JsonProperty("assertionScheme")]
        public string AssertionScheme { get; set; }
        [JsonProperty("authenticationAlgorithm")]
        public ushort AuthenticationAlgorithm { get; set; }
        [JsonProperty("authenticationAlgorithms")]
        public ushort[] AuthenticationAlgorithms { get; set; }
        [JsonProperty("publicKeyAlgAndEncoding")]
        public ushort PublicKeyAlgAndEncoding { get; set; }
        [JsonProperty("publicKeyAlgAndEncodings")]
        public ushort[] PublicKeyAlgAndEncodings { get; set; }
        [JsonProperty("attestationTypes")]
        public ushort[] AttestationTypes { get; set; }
        [JsonProperty("userVerificationDetails")]
        public VerificationMethodDescriptor[][] UserVerificationDetails { get; set; }
        [JsonProperty("keyProtection")]
        public ushort KeyProtection { get; set; }
        [JsonProperty("isKeyRestricted")]
        public bool IsKeyRestricted { get; set; }
        [JsonProperty("isFreshUserVerificationRequired")]
        public bool IsFreshUserVerificationRequired { get; set; }
        [JsonProperty("matcherProtection")]
        public ushort MatcherProtection { get; set; }
        [JsonProperty("cryptoStrength")]
        public ushort CryptoStrength { get; set; }
        [JsonProperty("operatingEnv")]
        public string OperatingEnv { get; set; }
        [JsonProperty("attachmentHint")]
        public ulong AttachmentHint { get; set; }
        [JsonProperty("isSecondFactorOnly")]
        public bool IsSecondFactorOnly { get; set; }
        [JsonProperty("tcDisplay")]
        public ushort TcDisplay { get; set; }
        [JsonProperty("tcDisplayContentType")]
        public string TcDisplayContentType { get; set; }
        [JsonProperty("tcDisplayPNGCharacteristics")]
        public DisplayPNGCharacteristicsDescriptor[] TcDisplayPNGCharacteristics { get; set; }
        [JsonProperty("attestationRootCertificates")]
        public string[] AttestationRootCertificates { get; set; }
        [JsonProperty("ecdaaTrustAnchors")]
        public EcdaaTrustAnchor[] EcdaaTrustAnchors { get; set; }
        [JsonProperty("icon")]
        public string Icon { get; set; }
        [JsonProperty("supportedExtensions")]
        public ExtensionDescriptor[] SupportedExtensions { get; set; }
        public string Hash { get; set; }
    }
}
