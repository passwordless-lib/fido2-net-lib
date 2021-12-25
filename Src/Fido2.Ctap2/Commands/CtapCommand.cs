using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

public abstract class CtapCommand
{
    public abstract CtapCommandType Type { get; }

    protected abstract CborObject? GetObject();

    public byte[] GetPayload()
    {
        var @object = GetObject();

        if (@object is null)
        {
            return new byte[] { (byte)Type };
        }
    
        var encodedObject = @object.Encode();

        var result = new byte[encodedObject.Length + 1];

        result[0] = (byte)Type;

        encodedObject.AsSpan().CopyTo(result.AsSpan(1));

        return result;      
    }
}
