using System;
using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography.X509Certificates;

namespace Fido2NetLib;

internal static class X509CertificateHelper
{
    public static X509Certificate2 CreateFromBase64String(ReadOnlySpan<byte> base64String)
    {
        var rentedBuffer = ArrayPool<byte>.Shared.Rent(Base64.GetMaxDecodedFromUtf8Length(base64String.Length));

        if (Base64.DecodeFromUtf8(base64String, rentedBuffer, out _, out int bytesWritten) != OperationStatus.Done)
        {
            ArrayPool<byte>.Shared.Return(rentedBuffer, true);

            throw new Exception("Invalid base64 data found parsing X509 certificate");
        }

        try
        {
            return CreateFromRawData(rentedBuffer.AsSpan(0, bytesWritten));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentedBuffer, true);
        }
    }

    public static X509Certificate2 CreateFromRawData(ReadOnlySpan<byte> rawData)
    {
        try
        {
            return new X509Certificate2(rawData);
        }
        catch (Exception ex)
        {
            throw new Exception("Could not parse X509 certificate", ex);
        }
    }
}
