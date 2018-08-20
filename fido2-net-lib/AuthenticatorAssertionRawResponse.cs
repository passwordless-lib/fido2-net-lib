using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// Transport class for AssertionResponse
    /// </summary>
    public class AuthenticatorAssertionRawResponse
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Id { get; set; }

        // might be wrong to base64url encode this...
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] RawId { get; set; }

        public AssertionResponse Response { get; set; }
        public string Type { get; set; }
        public class AssertionResponse
        {
            [JsonConverter(typeof(Base64UrlConverter))]
            public byte[] AuthenticatorData { get; set; }

            [JsonConverter(typeof(Base64UrlConverter))]
            public byte[] Signature { get; set; }

            [JsonProperty("clientDataJson")]
            [JsonConverter(typeof(Base64UrlConverter))]
            public byte[] ClientDataJson { get; set; }

            [JsonProperty("userHandle")]
            [JsonConverter(typeof(Base64UrlConverter), Required.AllowNull)]
            public byte[] UserHandle { get; set; }
        }
    }
}
