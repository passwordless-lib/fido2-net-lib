using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

public sealed class VerifyAttestationResult
{
    public VerifyAttestationResult(AttestationType type, X509Certificate2[] certificates)
        : this(type, certificates, null)
    {
    }

    public VerifyAttestationResult(AttestationType type, X509Certificate2[] certificates, byte[]? enterpriseAttestationSerialNumber)
        : this(type, certificates, enterpriseAttestationSerialNumber, null)
    {
    }

    public VerifyAttestationResult(
        AttestationType type,
        X509Certificate2[] certificates,
        byte[]? enterpriseAttestationSerialNumber,
        ulong? firmwareVersion)
    {
        Type = type;
        Certificates = certificates;
        EnterpriseAttestationSerialNumber = enterpriseAttestationSerialNumber;
        FirmwareVersion = firmwareVersion;
    }

    public AttestationType Type { get; }

    public X509Certificate2[] Certificates { get; }

    /// <summary>
    /// The value of the id-fido-gen-ce-sernum extension (OID 1.3.6.1.4.1.45724.1.1.2) in the attestation
    /// certificate, or <see langword="null"/> when the certificate does not carry one. This uniquely identifies
    /// a single device against a particular AAGUID and is only permitted in attestations conveyed for
    /// enterprise use.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-enterprise-packed-attestation-cert-requirements"/>
    /// </remarks>
    public byte[]? EnterpriseAttestationSerialNumber { get; }

    /// <summary>
    /// The value of the id-fido-gen-ce-fw-version extension (OID 1.3.6.1.4.1.45724.1.1.5) in the attestation
    /// certificate, or <see langword="null"/> when the certificate does not carry one. It differentiates the
    /// firmware of one authenticator model and is incremented for each new firmware release.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements"/>
    /// </remarks>
    public ulong? FirmwareVersion { get; }

    public void Deconstruct(out AttestationType type, out X509Certificate2[] certificates)
    {
        (type, certificates) = (Type, Certificates);
    }
}
