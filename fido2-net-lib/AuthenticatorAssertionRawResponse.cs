namespace fido2NetLib
{
    public class AuthenticatorAssertionRawResponse
    {
        public string Id { get; set; }
        public string RawId { get; set; }

        public AssertionResponse Response { get; set; }

        public class AssertionResponse
        {
            public byte[] AuthenticatorData { get; set; }
            public byte[] Signature { get; set; }

            public byte[] ClientDataJson { get; set; }

            public string UserHandle { get; set; }
        }
    }
}
