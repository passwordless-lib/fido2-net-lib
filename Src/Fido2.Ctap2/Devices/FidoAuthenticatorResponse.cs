using Fido2NetLib.Cbor;
using Fido2NetLib.Ctap2.Exceptions;

namespace Fido2NetLib.Ctap2;

public sealed class FidoAuthenticatorResponse
{
    public FidoAuthenticatorResponse(CtapStatusCode status)
    {
        Status = status;
        Data = Array.Empty<byte>().AsMemory();
    }

    public FidoAuthenticatorResponse(byte[] message)
    {
        Status = (CtapStatusCode)message[0];
        Data = message.AsMemory(1);
    }

    public CtapStatusCode Status { get; }

    public ReadOnlyMemory<byte> Data { get; }

    public CborObject GetCborObject()
    {
        return CborObject.Decode(Data);
    }

    public void CheckStatus()
    {
        if (Status != CtapStatusCode.OK)
        {
            throw new CtapException(Status);
        }
    }
}
