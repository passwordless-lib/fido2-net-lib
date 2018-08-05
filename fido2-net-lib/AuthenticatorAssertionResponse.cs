using System;
using System.Text;

namespace fido2NetLib
{
    internal class AuthenticatorAssertionResponse : AuthenticatorResponse
    {
        private AuthenticatorAssertionResponse(byte[] clientDataJson) : base(clientDataJson)
        {

        }

        public AuthenticatorAssertionRawResponse Raw { get; set; }
        public byte[] AuthenticatorData { get; set; }
        public byte[] Signature { get; set; }
        public string UserHandle { get; set; }

        internal static AuthenticatorAssertionResponse Parse(AuthenticatorAssertionRawResponse rawResponse)
        {
            var response = new AuthenticatorAssertionResponse(rawResponse.Response.ClientDataJson)
            {
                // we will need to access raw in Verify()
                Raw = rawResponse,
                AuthenticatorData = rawResponse.Response.AuthenticatorData,
                Signature = rawResponse.Response.Signature
            };


            //response.Raw = rawResponse;

            //var cborAttestion = PeterO.Cbor.CBORObject.DecodeFromBytes(rawResponse.Response);
            //response.AttestionObject = new ParsedAttestionObject()
            //{
            //    Fmt = cborAttestion["fmt"].AsString(),
            //    AttStmt = cborAttestion["attStmt"], // convert to dictionary?
            //    AuthData = cborAttestion["authData"].GetByteString()
            //};


            return response;
        }

        public void Verify(string challenge, string origin)
        {
            throw new NotImplementedException();
        }
    }
}
