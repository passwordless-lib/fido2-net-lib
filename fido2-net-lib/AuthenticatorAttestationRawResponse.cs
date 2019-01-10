using Newtonsoft.Json;
using Fido2NetLib.Objects;

namespace Fido2NetLib
{
    /// <summary>
    /// The raw transportation dto for <see cref="AuthenticatorAttestationResponse"/>
    /// </summary>
    public class AuthenticatorAttestationRawResponse
    {
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Id { get; set; }

        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] RawId { get; set; }

        public PublicKeyCredentialType Type { get; set; }

        public ResponseData Response { get; set; }

        public class ResponseData
        {
            [JsonConverter(typeof(Base64UrlConverter))]
            public byte[] AttestationObject { get; set; }
            [JsonConverter(typeof(Base64UrlConverter))]
            public byte[] ClientDataJson { get; set; }
        }
    }


    //public class Fido2CreateResponse : Fido2Response
    //{
    //    protected Fido2CreateResponse(object request, Expectations expectations) : base(request, expectations)
    //    {
    //        this.RequiredExpectations = new string[] { "origin", "challenge", "flags" };
    //    }

    //    public string[] RequiredExpectations { get; private set; }

    //    //private object parse()
    //    //{
    //    //    this.validateCreateRequest();
    //    //    base.parse();
    //    //    this.authnrData = parser.parseAttestationObject(this.request.response.attestationObject);
    //    //}

    //    //async validate()
    //    //{
    //    //    await this.validateCreateType();
    //    //    await super.validate();
    //    //    await this.validateAttestation();
    //    //    await this.validateInitialCounter();
    //    //    await this.validatePublicKey();
    //    //    await this.validateAaguid();
    //    //    await this.validateCredId();
    //    //}

    //    //static create(req, exp)
    //    //{
    //    //    return new Fido2CreateResponse(lockSym).create(req, exp);
    //    //}
    //}
    //public class Fido2Response
    //{
    //    public object Request { get; }
    //    public Expectations Expectations { get; }

    //    protected Fido2Response(object request, Expectations expectations)
    //    {
    //        Expectations = expectations;
    //        Request = request;

    //        // validate that input expectations and request are complete and in the right format
    //        //await this.validateExpectations();

    //        // parse and validate all the request fields (CBOR, etc.)
    //        //await this.parse();
    //        //await this.validate();

    //        // ensure the parsing and validation went well
    //        //await this.validateAudit();
    //    }

    //    protected object Parse()
    //    {
    //        return Parser.ParseClientResponse(this.Request);
    //    }

    //    static Fido2Response Create(object Request, Expectations expectations)
    //    {
    //        return new Fido2Response(Request, expectations);
    //    }
    //}
}
