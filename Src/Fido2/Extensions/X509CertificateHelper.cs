using System;
using System.Security.Cryptography.X509Certificates;

namespace Fido2NetLib;

internal static class X509CertificateHelper
{
    public static X509Certificate2 CreateFromBase64String(string base64String)
    {
        byte[] rawData;

        try
        {
            rawData = Convert.FromBase64String(base64String);
        }
        catch 
        {
            throw new Exception("Invalid base64 data found parsing X509 certificate");
        }

        return CreateFromRawData(rawData);
    }

    public static X509Certificate2 CreateFromRawData(byte[] rawData)
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
