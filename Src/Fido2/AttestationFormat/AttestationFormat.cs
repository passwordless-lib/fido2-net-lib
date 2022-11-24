#nullable disable

using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib;

public abstract class AttestationVerifier
{
    public CborMap attStmt;
    public byte[] authenticatorData;
    public byte[] clientDataHash;

    internal CborObject Sig => attStmt["sig"];
    internal CborObject X5c => attStmt["x5c"];
    internal CborObject Alg => attStmt["alg"];
    internal CborObject EcdaaKeyId => attStmt["ecdaaKeyId"];
    internal AuthenticatorData AuthData => new AuthenticatorData(authenticatorData);
    internal CborMap CredentialPublicKey => AuthData.AttestedCredentialData.CredentialPublicKey.GetCborObject();
    internal byte[] Data => DataHelper.Concat(authenticatorData, clientDataHash);

    internal static byte[] AaguidFromAttnCertExts(X509ExtensionCollection exts)
    {
        byte[] aaguid = null;
        var ext = exts.Cast<X509Extension>().FirstOrDefault(e => e.Oid.Value is "1.3.6.1.4.1.45724.1.1.4"); // id-fido-gen-ce-aaguid
        if (ext != null)
        {
            var decodedAaguid = Asn1Element.Decode(ext.RawData);
            decodedAaguid.CheckTag(Asn1Tag.PrimitiveOctetString);
            aaguid = decodedAaguid.GetOctetString();

            // The extension MUST NOT be marked as critical
            if (ext.Critical)
                throw new Fido2VerificationException("extension MUST NOT be marked as critical");
        }

        return aaguid;
    }

    internal static bool IsAttnCertCACert(X509ExtensionCollection exts)
    {
        var ext = exts.Cast<X509Extension>().FirstOrDefault(e => e.Oid.Value is "2.5.29.19");
        if (ext is X509BasicConstraintsExtension baseExt)
        {
            return baseExt.CertificateAuthority;
        }

        return true;
    }

    internal static byte U2FTransportsFromAttnCert(X509ExtensionCollection exts)
    {
        var u2ftransports = new byte();
        var ext = exts.Cast<X509Extension>().FirstOrDefault(e => e.Oid.Value is "1.3.6.1.4.1.45724.2.1.1");
        if (ext != null)
        {
            var decodedU2Ftransports = Asn1Element.Decode(ext.RawData);
            decodedU2Ftransports.CheckPrimitive();

            // some certificates seem to have this encoded as an octet string
            // instead of a bit string, attempt to correct
            if (decodedU2Ftransports.Tag == Asn1Tag.PrimitiveOctetString)
            {
                ext.RawData[0] = (byte)UniversalTagNumber.BitString;
                decodedU2Ftransports = Asn1Element.Decode(ext.RawData);
            }

            decodedU2Ftransports.CheckTag(Asn1Tag.PrimitiveBitString);

            u2ftransports = decodedU2Ftransports.GetBitString()[0];
        }

        return u2ftransports;
    }

    public virtual (AttestationType, X509Certificate2[]) Verify(CborMap attStmt, byte[] authenticatorData, byte[] clientDataHash)
    {
        this.attStmt = attStmt;
        this.authenticatorData = authenticatorData;
        this.clientDataHash = clientDataHash;
        return Verify();
    }

    public abstract (AttestationType, X509Certificate2[]) Verify();
}
