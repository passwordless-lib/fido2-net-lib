namespace Fido2NetLib.Cbor;

public sealed class CborNull : CborObject
{
    public static readonly CborNull Instance = new();

    public override CborType Type => CborType.Null;
}
