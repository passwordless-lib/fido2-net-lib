namespace fido2_net_lib;

internal static class CertInfoHelper
{
    public static byte[] CreateCertInfo(
        ReadOnlySpan<byte> magic,
        ReadOnlySpan<byte> type,
        ReadOnlySpan<byte> qualifiedSigner,
        ReadOnlySpan<byte> extraData,
        ReadOnlySpan<byte> clock,
        ReadOnlySpan<byte> resetCount,
        ReadOnlySpan<byte> restartCount,
        ReadOnlySpan<byte> safe,
        ReadOnlySpan<byte> firmwareRevision,
        ReadOnlySpan<byte> tPM2BName,
        ReadOnlySpan<byte> attestedQualifiedNameBuffer)
    {
        var stream = new MemoryStream();

        stream.Write(magic);
        stream.Write(type);
        stream.Write(qualifiedSigner);
        stream.Write(extraData);
        stream.Write(clock);
        stream.Write(resetCount);
        stream.Write(restartCount);
        stream.Write(safe);
        stream.Write(firmwareRevision);
        stream.Write(tPM2BName);
        stream.Write(attestedQualifiedNameBuffer);

        return stream.ToArray();
    }
}
