using System.Text;

namespace fido2NetLib
{
    internal class AuthenticatorResponse
    {

        public AuthenticatorResponse(byte[] clientDataJson)
        {
            var stringx = Encoding.UTF8.GetString(clientDataJson);
            var response = Newtonsoft.Json.JsonConvert.DeserializeObject<AuthenticatorResponse>(stringx);

            this.Type = response.Type;
            this.Challenge = response.Challenge;
            this.Origin = response.Origin;
        }

        public string Type { get; set; }
        public string Challenge { get; set; }
        public string Origin { get; set; }

        // todo: add TokenBinding https://www.w3.org/TR/webauthn/#dictdef-tokenbinding
    }
}
