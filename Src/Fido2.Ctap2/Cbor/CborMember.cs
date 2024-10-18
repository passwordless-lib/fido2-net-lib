namespace Fido2NetLib.Ctap2;

public sealed class CborMember : Attribute
{
    public object _key;

    public CborMember(byte key)
    {
        _key = key;
    }

    public CborMember(string key)
    {
        _key = key;
    }
}
