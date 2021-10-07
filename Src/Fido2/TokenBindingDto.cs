namespace Fido2NetLib
{
    public sealed class TokenBindingDto
    {
        public TokenBindingDto(string status, string id)
        {
            Status = status;
            Id = id;
        }

        /// <summary>
        /// Either "present" or "supported". https://www.w3.org/TR/webauthn/#enumdef-tokenbindingstatus
        /// supported: Indicates the client supports token binding, but it was not negotiated when communicating with the Relying Party.
        /// present: Indicates token binding was used when communicating with the Relying Party. In this case, the id member MUST be present
        /// </summary>
        public string Status { get; }

        /// <summary>
        /// This member MUST be present if status is present, and MUST a base64url encoding of the Token Binding ID that was used when communicating with the Relying Party.
        /// </summary>
        public string Id { get; }

        public void Verify(byte[] requestTokenbinding)
        {
            // validation by the FIDO conformance tool (more than spec says)
            switch (Status)
            {
                case "present":
                    if (string.IsNullOrEmpty(Id))
                        throw new Fido2VerificationException("TokenBinding status was present but Id is missing");
                    var b64 = Base64Url.Encode(requestTokenbinding);
                    if (Id != b64)
                        throw new Fido2VerificationException("Tokenbinding Id does not match");
                    break;
                case "supported":
                case "not-supported":
                    break;
                default:
                    throw new Fido2VerificationException("Malformed tokenbinding status field");
            }
        }
    }
}
