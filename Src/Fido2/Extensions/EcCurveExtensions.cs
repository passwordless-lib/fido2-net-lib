using System;
using System.Security.Cryptography;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

internal static class EcCurveExtensions
{
    public static COSE.EllipticCurve ToCoseCurve(this ECCurve curve)
    {
        if (curve.Oid.FriendlyName is "secP256k1")
            return COSE.EllipticCurve.P256K;

        if (curve.Oid.Value!.Equals(ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal))
            return COSE.EllipticCurve.P256;

        else if (curve.Oid.Value.Equals(ECCurve.NamedCurves.nistP384.Oid.Value, StringComparison.Ordinal))
            return COSE.EllipticCurve.P384;

        else if (curve.Oid.Value.Equals(ECCurve.NamedCurves.nistP521.Oid.Value, StringComparison.Ordinal))
            return COSE.EllipticCurve.P521;
        
        throw new Exception($"Invalid ECCurve. Was {curve.Oid}");
    }
}
