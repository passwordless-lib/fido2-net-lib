namespace Fido2NetLib.Objects
{
    public class AttestationType : TypedString
    {
        public static readonly AttestationType None = new AttestationType("none");
        public static readonly AttestationType Basic = new AttestationType("basic");
        public static readonly AttestationType Self = new AttestationType("self");
        public static readonly AttestationType AttCa = new AttestationType("attca");
        public static readonly AttestationType ECDAA = new AttestationType("ecdaa");

        private AttestationType(string value) : base(value)
        {
        }
    }
}
