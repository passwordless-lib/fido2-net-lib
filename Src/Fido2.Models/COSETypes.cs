using Fido2NetLib.Exceptions;

namespace Fido2NetLib.Objects;

/// <summary>
/// CBOR Object Signing and Encryption RFC8152 https://tools.ietf.org/html/rfc8152
/// </summary>
public static class COSE
{
    /// <summary>
    /// COSE Algorithms https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    /// </summary>
    public enum Algorithm
    {
        /// <summary>
        /// RSASSA-PKCS1-v1_5 w/ SHA-1
        /// </summary>
        RS1 = -65535,
        /// <summary>
        /// RSASSA-PKCS1-v1_5 w/ SHA-512
        /// </summary>
        RS512 = -259,
        /// <summary>
        /// RSASSA-PKCS1-v1_5 w/ SHA-384
        /// </summary>
        RS384 = -258,
        /// <summary>
        /// RSASSA-PKCS1-v1_5 w/ SHA-256
        /// </summary>
        RS256 = -257,
        /// <summary>
        /// RSASSA-PSS w/ SHA-512
        /// </summary>
        PS512 = -39,
        /// <summary>
        /// RSASSA-PSS w/ SHA-384
        /// </summary>
        PS384 = -38,
        /// <summary>
        /// RSASSA-PSS w/ SHA-256
        /// </summary>
        PS256 = -37,
        /// <summary>
        /// ECDSA w/ SHA-512
        /// </summary>
        ES512 = -36,
        /// <summary>
        /// ECDSA w/ SHA-384
        /// </summary>
        ES384 = -35,
        /// <summary>
        /// EdDSA
        /// </summary>
        EdDSA = -8,
        /// <summary>
        /// ECDSA w/ SHA-256
        /// </summary>
        ES256 = -7,
        /// <summary>
        /// ECDSA using secp256k1 curve and SHA-256
        /// </summary>
        ES256K = -47,

        // The identifiers below are the "fully-specified" algorithms: unlike ES256/ES384/ES512 and EdDSA, which
        // leave the curve to the key's crv parameter, each of these fixes the curve as part of the algorithm.
        // See the IANA COSE Algorithms registry.
        //
        // WebAuthn Level 3 recommends against offering ESP256, ESP384, ESP512 or Ed25519 in pubKeyCredParams
        // (§18.1), but an authenticator may still return a credential using one, so they must be understood.

        /// <summary>
        /// ECDSA using P-256 curve and SHA-256. Fully-specified equivalent of <see cref="ES256"/>.
        /// </summary>
        ESP256 = -9,

        /// <summary>
        /// EdDSA using the Ed25519 curve. Fully-specified equivalent of <see cref="EdDSA"/> with crv Ed25519.
        /// </summary>
        Ed25519 = -19,

        /// <summary>
        /// ECDSA using P-384 curve and SHA-384. Fully-specified equivalent of <see cref="ES384"/>.
        /// </summary>
        ESP384 = -51,

        /// <summary>
        /// ECDSA using P-521 curve and SHA-512. Fully-specified equivalent of <see cref="ES512"/>.
        /// </summary>
        ESP512 = -52,

        /// <summary>
        /// EdDSA using the Ed448 curve. Signature verification is not implemented: NSec.Cryptography has no
        /// Ed448 support.
        /// </summary>
        Ed448 = -53,

        // Post-quantum signature algorithms, registered by RFC 9964. All three use key type
        // <see cref="KeyType.AKP"/>, with the public key carried at label -1 (see KeyTypeParameter.Pub)
        // rather than as curve coordinates.
        //
        // Note that these are COSE registrations, not WebAuthn ones: WebAuthn L3 §5.8.5 defers to the COSE
        // registry, and how an authenticator produces such a credential is still only an individual
        // Internet-Draft. Verification of an assertion signature, which is all a Relying Party does, follows
        // from RFC 9964 and needs nothing from that draft.

        /// <summary>
        /// ML-DSA-44, the FIPS 204 module-lattice signature scheme at security category 2.
        /// </summary>
        /// <remarks>
        /// Verification requires .NET 10 or later, which provides <c>System.Security.Cryptography.MLDsa</c>.
        /// On earlier targets the library reports <see cref="Exceptions.Fido2ErrorCode.UnimplementedAlgorithm"/>.
        /// </remarks>
        MLDSA44 = -48,

        /// <summary>
        /// ML-DSA-65, the FIPS 204 module-lattice signature scheme at security category 3.
        /// </summary>
        /// <inheritdoc cref="MLDSA44" path="/remarks"/>
        MLDSA65 = -49,

        /// <summary>
        /// ML-DSA-87, the FIPS 204 module-lattice signature scheme at security category 5.
        /// </summary>
        /// <inheritdoc cref="MLDSA44" path="/remarks"/>
        MLDSA87 = -50,
    }
    /// <summary>
    /// COSE Key Common Parameters https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
    /// </summary>
    public enum KeyCommonParameter
    {
        /// <summary>
        /// This value is reserved
        /// </summary>
        Reserved = 0,
        /// <summary>
        /// Identification of the key type
        /// </summary>
        KeyType = 1,
        /// <summary>
        /// Key identification value - match to kid in message
        /// </summary>
        KeyId = 2,
        /// <summary>
        /// Key usage restriction to this algorithm
        /// </summary>
        Alg = 3,
        /// <summary>
        /// Restrict set of permissible operations
        /// </summary>
        KeyOps = 4,
        /// <summary>
        /// Base IV to be XORed with Partial IVs
        /// </summary>
        BaseIV = 5
    }
    /// <summary>
    /// COSE Key Type Parameters https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
    /// </summary>
    public enum KeyTypeParameter
    {
        /// <summary>
        /// EC identifier
        /// </summary>
        Crv = -1,
        /// <summary>
        /// Key Value
        /// </summary>
        K = -1,
        /// <summary>
        /// x-coordinate
        /// </summary>
        X = -2,
        /// <summary>
        /// y-coordinate
        /// </summary>
        Y = -3,
        /// <summary>
        /// the RSA modulus n
        /// </summary>
        N = -1,
        /// <summary>
        /// the RSA public exponent e
        /// </summary>
        E = -2,
        /// <summary>
        /// The public key of an <see cref="KeyType.AKP"/> key, as a byte string whose encoding is defined by
        /// the algorithm. Aliases -1, as <see cref="Crv"/>, <see cref="K"/> and <see cref="N"/> already do:
        /// the label's meaning depends on the key type.
        /// </summary>
        Pub = -1
    }
    /// <summary>
    /// COSE Key Types https://www.iana.org/assignments/cose/cose.xhtml#key-type
    /// </summary>
    public enum KeyType
    {
        /// <summary>
        /// This value is reserved
        /// </summary>
        Reserved = 0,
        /// <summary>
        /// Octet Key Pair
        /// </summary>
        OKP = 1,
        /// <summary>
        /// Elliptic Curve Keys w/ x- and y-coordinate pair
        /// </summary>
        EC2 = 2,
        /// <summary>
        /// RSA Key
        /// </summary>
        RSA = 3,
        /// <summary>
        /// Symmetric Keys
        /// </summary>
        Symmetric = 4,
        /// <summary>
        /// Algorithm Key Pair, the key type the algorithm itself defines the encoding for. Used by the ML-DSA
        /// algorithms, whose public key is a single opaque byte string rather than a set of curve parameters.
        /// <see href="https://www.rfc-editor.org/rfc/rfc9964.html"/>
        /// </summary>
        AKP = 7
    }

    /// <summary>
    /// COSE Elliptic Curves https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
    /// </summary>
    public enum EllipticCurve
    {
        /// <summary>
        /// This value is reserved
        /// </summary>
        Reserved = 0,
        /// <summary>
        /// NIST P-256 also known as secp256r1
        /// </summary>
        P256 = 1,
        /// <summary>
        /// NIST P-384 also known as secp384r1
        /// </summary>
        P384 = 2,
        /// <summary>
        /// NIST P-521 also known as secp521r1
        /// </summary>
        P521 = 3,
        /// <summary>
        /// X25519 for use w/ ECDH only
        /// </summary>
        X25519 = 4,
        /// <summary>
        /// X448 for use w/ ECDH only
        /// </summary>
        X448 = 5,
        /// <summary>
        /// Ed25519 for use w/ EdDSA only
        /// </summary>
        Ed25519 = 6,
        /// <summary>
        /// Ed448 for use w/ EdDSA only
        /// </summary>
        Ed448 = 7,
        /// <summary>
        /// secp256k1
        /// </summary>
        P256K = 8
    }

    public static KeyType GetKeyTypeFromOid(string oid)
    {
        return oid switch
        {
            "1.2.840.10045.2.1" => KeyType.EC2, // ecPublicKey
            "1.2.840.113549.1.1.1" => KeyType.RSA,
            "1.3.101.112" => KeyType.OKP,
            _ => throw new Fido2VerificationException(Fido2ErrorCode.InvalidCredentialPublicKey, $"Unknown public key algorithm OID {oid}")
        };
    }
}
