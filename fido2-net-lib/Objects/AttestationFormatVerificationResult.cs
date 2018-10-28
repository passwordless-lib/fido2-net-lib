using System.Security.Cryptography.X509Certificates;

namespace Fido2NetLib.Objects
{
    public class AttestationFormatVerificationResult
    {
        public AttestationType attnType;
        public X509Certificate2[] trustPath;
    }
}
