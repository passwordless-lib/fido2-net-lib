using System;
using System.Runtime.Serialization;

using Fido2NetLib.Exceptions;

namespace Fido2NetLib;

[Serializable]
public class Fido2VerificationException : Exception
{
    public Fido2VerificationException()
    {
    }

    public Fido2VerificationException(string message) : base(message)
    {
    }

    public Fido2VerificationException(Fido2ErrorCode code, string message) : base(message)
    {
        Code = code;
    }

    public Fido2VerificationException(Fido2ErrorCode code, string message, Exception innerException) : base(message, innerException)
    {
        Code = code;
    }

    public Fido2VerificationException(string message, Exception innerException) : base(message, innerException)
    {
    }

    protected Fido2VerificationException(SerializationInfo info, StreamingContext context) : base(info, context)
    {
    }

    public Fido2ErrorCode Code { get; }
}
