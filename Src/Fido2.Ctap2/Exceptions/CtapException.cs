namespace Fido2NetLib.Ctap2.Exceptions;

public sealed class CtapException : Exception
{
    public CtapException(CtapStatusCode status)
        : base(status.ToString()) { }
}
