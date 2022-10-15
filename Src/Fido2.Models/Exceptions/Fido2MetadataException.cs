using System;
using System.Runtime.Serialization;

namespace Fido2NetLib;

[Serializable]
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

    protected Fido2MetadataException(SerializationInfo info, StreamingContext context) : base(info, context)
    {
    }
}
