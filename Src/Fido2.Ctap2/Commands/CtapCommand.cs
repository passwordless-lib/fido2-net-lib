using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

public abstract class CtapCommand
{
    public abstract CtapCommandType Type { get; }

    protected virtual CborObject? GetParameters() => null;

    public byte[] GetPayload()
    {
        CborObject? parameters = GetParameters();

        if (parameters is null)
        {
            return new byte[] { (byte)Type };
        }

        var encodedObject = parameters.Encode();

        var result = new byte[encodedObject.Length + 1];

        result[0] = (byte)Type;

        encodedObject.AsSpan().CopyTo(result.AsSpan(1));

        return result;
    }
}
