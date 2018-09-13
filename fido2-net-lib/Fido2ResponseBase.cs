using Newtonsoft.Json;

namespace Fido2NetLib
{
    public abstract class Fido2ResponseBase
    {
        [JsonProperty("status")]
        public string Status { get; set; }

        [JsonProperty("errorMessage")]
        public string ErrorMessage { get; set; }
    }
}
