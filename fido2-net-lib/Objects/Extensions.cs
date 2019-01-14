using Newtonsoft.Json;

namespace Fido2NetLib.Objects
{
    public class AuthenticationExtensionsClientInputs
    {
        [JsonProperty("example.extension", NullValueHandling = NullValueHandling.Ignore)]
        public string ExampleExtension { get; set; }
    }
    public class AuthenticationExtensionsClientOutputs
    {
        [JsonProperty("example.extension", NullValueHandling = NullValueHandling.Ignore)]
        public string ExampleExtension { get; set; }
    }
    public class AuthenticationExtensionsAuthenticatorInputs
    {

    }
}
