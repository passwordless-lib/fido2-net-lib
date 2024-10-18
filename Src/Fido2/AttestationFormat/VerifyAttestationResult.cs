using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

public sealed class VerifyAttestationResult
{
    public VerifyAttestationResult(AttestationType type, X509Certificate2[] certificates)
    {
        Type = type;
        Certificates = certificates;
    }

    public AttestationType Type { get; }

    public X509Certificate2[] Certificates { get; }

    public void Deconstruct(out AttestationType type, out X509Certificate2[] certificates)
    {
        (type, certificates) = (Type, Certificates);
    }
}
