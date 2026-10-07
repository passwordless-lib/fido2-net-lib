using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// Verifies signatures for a COSE OKP (Octet Key Pair) credential public key -- EdDSA over an Edwards curve.
/// </summary>
/// <remarks>
/// <para>
/// .NET's own <c>System.Security.Cryptography</c> has no EdDSA support as of .NET 10, so this library does
/// not implement OKP verification itself; it dispatches to whichever <see cref="IOkpSignatureVerifier"/>s are
/// registered via <see cref="OkpSignatureVerifiers.Register"/>. The <c>Fido2.NSec</c> package is the reference
/// implementation, covering Ed25519 (the only OKP signature curve any authenticator in the wild produces
/// today) via <c>NSec.Cryptography</c>. It is a transitive dependency of the <c>Fido2</c> package, so EdDSA
/// verification works out of the box with no extra steps; <c>Fido2.WithoutNSec</c> is the same library
/// without that dependency, for the minority of consumers who cannot take it.
/// </para>
/// <para>
/// Keyed by curve rather than by COSE algorithm ID, because that is what this library already resolves both
/// the generic <see cref="COSE.Algorithm.EdDSA"/> (-8) and the fully-specified
/// <see cref="COSE.Algorithm.Ed25519"/> (-19) algorithm identifiers down to before an implementation is ever
/// consulted -- one provider entry serves both. A provider that only implements Ed25519 should return
/// <see langword="false"/> from <see cref="CanVerify"/> for every other curve, including
/// <see cref="COSE.EllipticCurve.Ed448"/>: nothing in this library assumes a single provider covers every
/// OKP curve, or that any given curve is covered at all. <see cref="COSE.EllipticCurve.X25519"/> and
/// <see cref="COSE.EllipticCurve.X448"/> are ECDH-only and never valid as a WebAuthn credential's signing
/// key, so no provider needs to handle them.
/// </para>
/// </remarks>
public interface IOkpSignatureVerifier
{
    /// <summary>
    /// Whether this provider can verify a signature for the given curve.
    /// </summary>
    bool CanVerify(COSE.EllipticCurve curve);

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="data"/> under <paramref name="publicKey"/>,
    /// interpreted per <paramref name="curve"/>.
    /// </summary>
    /// <param name="curve">The curve to verify under. <see cref="CanVerify"/> has already returned <see langword="true"/> for it.</param>
    /// <param name="publicKey">The raw public key bytes, as carried in the COSE_Key's <c>x</c> parameter.</param>
    /// <param name="data">The data the signature covers.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <exception cref="Fido2VerificationException"><paramref name="publicKey"/> is malformed for <paramref name="curve"/>.</exception>
    bool Verify(COSE.EllipticCurve curve, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
}
