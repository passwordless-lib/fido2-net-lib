using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

internal static class EcCurveExtensions
{
    public static COSE.EllipticCurve ToCoseCurve(this ECCurve curve)
    {
        if (curve.Oid.FriendlyName is "secP256k1")
            return COSE.EllipticCurve.P256K;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            if (curve.Oid.FriendlyName!.Equals(ECCurve.NamedCurves.nistP256.Oid.FriendlyName, StringComparison.Ordinal))
                return COSE.EllipticCurve.P256;

            else if (curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP384.Oid.FriendlyName, StringComparison.Ordinal))
                return COSE.EllipticCurve.P384;

            else if (curve.Oid.FriendlyName.Equals(ECCurve.NamedCurves.nistP521.Oid.FriendlyName, StringComparison.Ordinal))
                return COSE.EllipticCurve.P521;
        }
        else
        {
            if (curve.Oid.Value!.Equals(ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal))
                return COSE.EllipticCurve.P256;

            else if (curve.Oid.Value.Equals(ECCurve.NamedCurves.nistP384.Oid.Value, StringComparison.Ordinal))
                return COSE.EllipticCurve.P384;

            else if (curve.Oid.Value.Equals(ECCurve.NamedCurves.nistP521.Oid.Value, StringComparison.Ordinal))
                return COSE.EllipticCurve.P521;
        }

        throw new Exception($"Invalid ECCurve. Was {curve.Oid}");
    }
}
