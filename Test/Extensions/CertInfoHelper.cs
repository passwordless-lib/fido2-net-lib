namespace fido2_net_lib;

internal static class CertInfoHelper
{
    public static byte[] Create(byte[] magic, byte[] type, byte[] qualifiedSigner,
        byte[] extraData, byte[] clock, byte[] resetCount, byte[] restartCount,
        byte[] safe, byte[] firmwareRevision, byte[] tPM2BName, byte[] attestedQualifiedNameBuffer)
    {
        var raw = new MemoryStream();

        raw.Write(magic);
        raw.Write(type);
        raw.Write(qualifiedSigner);
        raw.Write(extraData);
        raw.Write(clock);
        raw.Write(resetCount);
        raw.Write(restartCount);
        raw.Write(safe);
        raw.Write(firmwareRevision);
        raw.Write(tPM2BName);
        raw.Write(attestedQualifiedNameBuffer);

        return raw.ToArray();
    }
}
