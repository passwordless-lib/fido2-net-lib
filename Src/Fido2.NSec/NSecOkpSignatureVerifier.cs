using System.Runtime.CompilerServices;
using System.Security.Cryptography;

using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

using NSec.Cryptography;

namespace Fido2NetLib.NSec;

/// <summary>
/// The <see cref="IOkpSignatureVerifier"/> this package provides: Ed25519 via <c>NSec.Cryptography</c>.
/// </summary>
/// <remarks>
/// Registers itself automatically the moment this assembly loads (see <see cref="AssemblyInitializer"/>) --
/// nothing to configure. Covers only <see cref="COSE.EllipticCurve.Ed25519"/>: NSec.Cryptography has no
/// Ed448 support as of this writing, so <see cref="CanVerify"/> returns <see langword="false"/> for it, the
/// same as it would for any curve no registered provider implements.
/// </remarks>
public sealed class NSecOkpSignatureVerifier : IOkpSignatureVerifier
{
    /// <inheritdoc/>
    public bool CanVerify(COSE.EllipticCurve curve) => curve == COSE.EllipticCurve.Ed25519;

    /// <inheritdoc/>
    public bool Verify(COSE.EllipticCurve curve, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (curve != COSE.EllipticCurve.Ed25519)
        {
            throw new ArgumentOutOfRangeException(nameof(curve), curve, $"{nameof(NSecOkpSignatureVerifier)} only supports {COSE.EllipticCurve.Ed25519}.");
        }

        PublicKey nsecPublicKey;

        try
        {
            nsecPublicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, publicKey, KeyBlobFormat.RawPublicKey);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or CryptographicException)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.InvalidCredentialPublicKey,
                "OKP credential public key is not a valid Ed25519 public key",
                ex);
        }

        return SignatureAlgorithm.Ed25519.Verify(nsecPublicKey, data, signature);
    }
}

/// <summary>
/// Registers <see cref="NSecOkpSignatureVerifier"/> the moment this assembly loads, so a project that just
/// references the Fido2.NSec package (directly, or transitively via Fido2) gets EdDSA support with no
/// startup code of its own to write.
/// </summary>
internal static class AssemblyInitializer
{
    [ModuleInitializer]
    internal static void Register() => OkpSignatureVerifiers.Register(new NSecOkpSignatureVerifier());
}
