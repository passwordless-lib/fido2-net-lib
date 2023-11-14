using System;

namespace Fido2NetLib;

public class Fido2MetadataException : Exception
{
    public Fido2MetadataException()
    {
    }

    public Fido2MetadataException(string message) : base(message)
    {
    }

    public Fido2MetadataException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
