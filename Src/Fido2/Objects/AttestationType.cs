namespace Fido2NetLib.Objects
{
    public sealed class AttestationType : TypedString
    {
        public static readonly AttestationType None  = new ("none");
        public static readonly AttestationType Basic = new ("basic");
        public static readonly AttestationType Self  = new ("self");
        public static readonly AttestationType AttCa = new ("attca");
        public static readonly AttestationType ECDAA = new ("ecdaa");

        private AttestationType(string value) : base(value)
        {
        }
    }
}
