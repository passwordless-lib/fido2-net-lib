namespace Fido2NetLib;

/// <summary>
/// Thrown when a <see cref="Fido2Configuration"/> is internally inconsistent, e.g. a configured
/// origin's scheme or relationship to the RP ID does not satisfy WebAuthn's requirements.
/// </summary>
public class Fido2ConfigurationException : Exception
{
    public Fido2ConfigurationException()
    {
    }

    public Fido2ConfigurationException(string message) : base(message)
    {
    }

    public Fido2ConfigurationException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
