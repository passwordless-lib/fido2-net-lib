using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib.AttestationFormat
{
    internal class Tpm : AttestationFormat
    {
        private readonly bool _requireValidAttestationRoot;

        public Tpm(CBORObject attStmt, byte[] authenticatorData, byte[] clientDataHash, bool requireValidAttestationRoot) 
            : base(attStmt, authenticatorData, clientDataHash)
        {
            _requireValidAttestationRoot = requireValidAttestationRoot;
        }
        // certificates from https://docs.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates

        // microsoft root is used by numerous manufacturers 
        private static readonly X509Certificate2 msRootCert = new X509Certificate2(Convert.FromBase64String(
                "MIIGSDCCBDCgAwIBAgIJANLAiKUvCLEqMA0GCSqGSIb3DQEBCwUAMIG/MQswCQYD" +
                "VQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDEWMBQGA1UE" +
                "CgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMTYwNAYDVQQDDC1GSURPIEZh" +
                "a2UgVFBNIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTgxMTAvBgkqhkiG" +
                "9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcwHhcNMTgw" +
                "NTI5MTQzMjU5WhcNNDUxMDE0MTQzMjU5WjCBvzELMAkGA1UEBhMCVVMxCzAJBgNV" +
                "BAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQxFjAUBgNVBAoMDUZJRE8gQWxsaWFu" +
                "Y2UxDDAKBgNVBAsMA0NXRzE2MDQGA1UEAwwtRklETyBGYWtlIFRQTSBSb290IENl" +
                "cnRpZmljYXRlIEF1dGhvcml0eSAyMDE4MTEwLwYJKoZIhvcNAQkBFiJjb25mb3Jt" +
                "YW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMIICIjANBgkqhkiG9w0BAQEFAAOC" +
                "Ag8AMIICCgKCAgEAyCtbMw6ckWpylo7ZCboe3khforOB1eUb0DZg4mLsf460nKnZ" +
                "JbztZh/3qqLQTUBEb1kxeGW31QiJ5UoiAcPAoo9aHIADVfjJEPvr865fOqt85f/q" +
                "O2qsF6ZjVpNk1/zQRP4xPRLZPhawQvZsnmV20vteV8K4KL9kWw/Yjo+m9LKt90OM" +
                "1tf7+F/uh1alocxc+WPmfpXxSHDfySTvnq6m8cQySAn3LyjAg1pYnT4P9QC0HbNK" +
                "z0KoL+EFylsmvps7wjAeRqNetu0BdmvBLtYC7AMxGpCzAuF5tYl+9/hWMI544QGn" +
                "ZrQnhIXfq704brI04NsUtBmCfZ5rEuc+Gzrz/asAPo6JSXyj9OSq+yPiWXen3g98" +
                "/BI7f7gZoV6rqrdCojkFlWZVBJgWgHio0JEy7OB4RPO0SIKichjKbvIyTcE+J7oP" +
                "Cgz5UCjBbSo94sJ8hs35W2y8aVYriRZ94z5w9IM/T/tZLkZDOzI03uot+PO2d1xX" +
                "K8YQ/QVzKnNcxXeve9l3x/CNzgknbp+IiL/NH509Zcn0YiGLfInHLPpEQ3p1PSU5" +
                "vtx+mWWpoRWvzwYpQD907skC9exZjm16F1ZKu+cvboeA1AHAHC/tE26Lxema5F/p" +
                "KXVFSu2XqK8JS6hO3EauL5ONaWxVIsQX4CIOxFdvS6mdmp8n+9SWr9FOuSMCAwEA" +
                "AaNFMEMwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0O" +
                "BBYEFEMRFpma7p1QN8JP/uJbFckJMz8yMA0GCSqGSIb3DQEBCwUAA4ICAQBlMRmP" +
                "NnAWOxnkQ5L/rFfrNxelNv65g1igxu9ADtLpTvgoDauoT3JdaIeano3jbXxEvOPK" +
                "oI0dwDmioYGZoZcTrMFtCLuygotZHVn+m5Lz1M+22mnR/REhrWzifDzqttEy0N1a" +
                "OOATF3cc2RMupn1LUci5Tl+Mlx5QzfOL36UduWO6Mt3wRBmMua7vRbxU3GScIUTW" +
                "aWUMT3MUdlYIITkMXon5S4zXvc2Z/xn98/Lj0GR/h3VnDlg+mZnIyKdHBJ/racTD" +
                "FH1kvlU4LEvY9K6yJIi7GQvlN0JvsL7XDetnOENJrRrq5N8xSu9X9puNFaFBufuA" +
                "NmE0EsF7MMybD4YfIhBWE4qSPEgaoa136Paf/pCPXz/BwSTlmCXoRJeybfgJsNoj" +
                "K72heXSpJrwGI2RPKRg0UJ2Bw7GRkzubuaAB9apvBVurCngZ8n28bkCG+12v0qMh" +
                "UwYKdlPP5mozrxK7shg+y9LBNO2x3b85Uu9hWZl3xys4P7hOtoG3y0IN05aCSvou" +
                "l3YCmR+NJ5aK1PePq2qvSaWfBZyZBwNFlWTZb+pxLjXwul+m2Pg/9bMp0oPK7XZt" +
                "Ar+IZ5HN+Tld2RL142d5ElizNNpiGDXlFTIqg7YzodejASdKNtn/S1z8yzHUuHE6" +
                "ogcYf5q/tvBkp/uRH9i6L+xUSMoGHkXP2Bj9AQ=="
            ));
        public static readonly Dictionary<string, X509Certificate2[]> TPMManufacturerRootMap = new Dictionary<string, X509Certificate2[]>
        {
            {"id:FFFFF1D0", new X509Certificate2[]{ // FIDO test
                new X509Certificate2(Convert.FromBase64String(
                "MIIGSDCCBDCgAwIBAgIJANLAiKUvCLEqMA0GCSqGSIb3DQEBCwUAMIG/MQswCQYD" +
                "VQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDEWMBQGA1UE" +
                "CgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMTYwNAYDVQQDDC1GSURPIEZh" +
                "a2UgVFBNIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTgxMTAvBgkqhkiG" +
                "9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcwHhcNMTgw" +
                "NTI5MTQzMjU5WhcNNDUxMDE0MTQzMjU5WjCBvzELMAkGA1UEBhMCVVMxCzAJBgNV" +
                "BAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQxFjAUBgNVBAoMDUZJRE8gQWxsaWFu" +
                "Y2UxDDAKBgNVBAsMA0NXRzE2MDQGA1UEAwwtRklETyBGYWtlIFRQTSBSb290IENl" +
                "cnRpZmljYXRlIEF1dGhvcml0eSAyMDE4MTEwLwYJKoZIhvcNAQkBFiJjb25mb3Jt" +
                "YW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMIICIjANBgkqhkiG9w0BAQEFAAOC" +
                "Ag8AMIICCgKCAgEAyCtbMw6ckWpylo7ZCboe3khforOB1eUb0DZg4mLsf460nKnZ" +
                "JbztZh/3qqLQTUBEb1kxeGW31QiJ5UoiAcPAoo9aHIADVfjJEPvr865fOqt85f/q" +
                "O2qsF6ZjVpNk1/zQRP4xPRLZPhawQvZsnmV20vteV8K4KL9kWw/Yjo+m9LKt90OM" +
                "1tf7+F/uh1alocxc+WPmfpXxSHDfySTvnq6m8cQySAn3LyjAg1pYnT4P9QC0HbNK" +
                "z0KoL+EFylsmvps7wjAeRqNetu0BdmvBLtYC7AMxGpCzAuF5tYl+9/hWMI544QGn" +
                "ZrQnhIXfq704brI04NsUtBmCfZ5rEuc+Gzrz/asAPo6JSXyj9OSq+yPiWXen3g98" +
                "/BI7f7gZoV6rqrdCojkFlWZVBJgWgHio0JEy7OB4RPO0SIKichjKbvIyTcE+J7oP" +
                "Cgz5UCjBbSo94sJ8hs35W2y8aVYriRZ94z5w9IM/T/tZLkZDOzI03uot+PO2d1xX" +
                "K8YQ/QVzKnNcxXeve9l3x/CNzgknbp+IiL/NH509Zcn0YiGLfInHLPpEQ3p1PSU5" +
                "vtx+mWWpoRWvzwYpQD907skC9exZjm16F1ZKu+cvboeA1AHAHC/tE26Lxema5F/p" +
                "KXVFSu2XqK8JS6hO3EauL5ONaWxVIsQX4CIOxFdvS6mdmp8n+9SWr9FOuSMCAwEA" +
                "AaNFMEMwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0O" +
                "BBYEFEMRFpma7p1QN8JP/uJbFckJMz8yMA0GCSqGSIb3DQEBCwUAA4ICAQBlMRmP" +
                "NnAWOxnkQ5L/rFfrNxelNv65g1igxu9ADtLpTvgoDauoT3JdaIeano3jbXxEvOPK" +
                "oI0dwDmioYGZoZcTrMFtCLuygotZHVn+m5Lz1M+22mnR/REhrWzifDzqttEy0N1a" +
                "OOATF3cc2RMupn1LUci5Tl+Mlx5QzfOL36UduWO6Mt3wRBmMua7vRbxU3GScIUTW" +
                "aWUMT3MUdlYIITkMXon5S4zXvc2Z/xn98/Lj0GR/h3VnDlg+mZnIyKdHBJ/racTD" +
                "FH1kvlU4LEvY9K6yJIi7GQvlN0JvsL7XDetnOENJrRrq5N8xSu9X9puNFaFBufuA" +
                "NmE0EsF7MMybD4YfIhBWE4qSPEgaoa136Paf/pCPXz/BwSTlmCXoRJeybfgJsNoj" +
                "K72heXSpJrwGI2RPKRg0UJ2Bw7GRkzubuaAB9apvBVurCngZ8n28bkCG+12v0qMh" +
                "UwYKdlPP5mozrxK7shg+y9LBNO2x3b85Uu9hWZl3xys4P7hOtoG3y0IN05aCSvou" +
                "l3YCmR+NJ5aK1PePq2qvSaWfBZyZBwNFlWTZb+pxLjXwul+m2Pg/9bMp0oPK7XZt" +
                "Ar+IZ5HN+Tld2RL142d5ElizNNpiGDXlFTIqg7YzodejASdKNtn/S1z8yzHUuHE6" +
                "ogcYf5q/tvBkp/uRH9i6L+xUSMoGHkXP2Bj9AQ=="
            ))}},
            {"id:414D4400", new X509Certificate2[]{ //AMD
                new X509Certificate2(Convert.FromBase64String(
                "MIIEiDCCA3CgAwIBAgIQJk05ojzrXVtJ1hAETuvRITANBgkqhkiG9w0BAQsFADB2" +
                "MRQwEgYDVQQLEwtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxEjAQBgNVBAcTCVN1" +
                "bm55dmFsZTELMAkGA1UECBMCQ0ExHzAdBgNVBAoTFkFkdmFuY2VkIE1pY3JvIERl" +
                "dmljZXMxDzANBgNVBAMTBkFNRFRQTTAeFw0xNDEwMjMxNDM0MzJaFw0zOTEwMjMx" +
                "NDM0MzJaMHYxFDASBgNVBAsTC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzESMBAG" +
                "A1UEBxMJU3Vubnl2YWxlMQswCQYDVQQIEwJDQTEfMB0GA1UEChMWQWR2YW5jZWQg" +
                "TWljcm8gRGV2aWNlczEPMA0GA1UEAxMGQU1EVFBNMIIBIjANBgkqhkiG9w0BAQEF" +
                "AAOCAQ8AMIIBCgKCAQEAssnOAYu5nRflQk0bVtsTFcLSAMx9odZ4Ey3n6/MA6FD7" +
                "DECIE70RGZgaRIID0eb+dyX3znMrp1TS+lD+GJSw7yDJrKeU4it8cMLqFrqGm4SE" +
                "x/X5GBa11sTmL4i60pJ5nDo2T69OiJ+iqYzgBfYJLqHQaeSRN6bBYyn3w1H4JNzP" +
                "DNvqKHvkPfYewHjUAFJAI1dShYO8REnNCB8eeolj375nymfAAZzgA8v7zmFX/1tV" +
                "LCy7Mm6n7zndT452TB1mek9LC5LkwlnyABwaN2Q8LV4NWpIAzTgr55xbU5VvgcIp" +
                "w+/qcbYHmqL6ZzCSeE1gRKQXlsybK+W4phCtQfMgHQIDAQABo4IBEDCCAQwwDgYD" +
                "VR0PAQH/BAQDAgEGMCMGCSsGAQQBgjcVKwQWBBRXjFRfeWlRQhIhpKV4rNtfaC+J" +
                "yDAdBgNVHQ4EFgQUV4xUX3lpUUISIaSleKzbX2gvicgwDwYDVR0TAQH/BAUwAwEB" +
                "/zA4BggrBgEFBQcBAQQsMCowKAYIKwYBBQUHMAGGHGh0dHA6Ly9mdHBtLmFtZC5j" +
                "b20vcGtpL29jc3AwLAYDVR0fBCUwIzAhoB+gHYYbaHR0cDovL2Z0cG0uYW1kLmNv" +
                "bS9wa2kvY3JsMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRw" +
                "czovL2Z0cG0uYW1kLmNvbS9wa2kvY3BzMA0GCSqGSIb3DQEBCwUAA4IBAQCWB9yA" +
                "oYYIt5HRY/OqJ5LUacP6rNmsMfPUDTcahXB3iQmY8HpUoGB23lhxbq+kz3vIiGAc" +
                "UdKHlpB/epXyhABGTcJrNPMfx9akLqhI7WnMCPBbHDDDzKjjMB3Vm65PFbyuqbLu" +
                "jN/sN6kNtc4hL5r5Pr6Mze5H9WXBo2F2Oy+7+9jWMkxNrmUhoUUrF/6YsajTGPeq" +
                "7r+i6q84W2nJdd+BoQQv4sk5GeuN2j2u4k1a8DkRPsVPc2I9QTtbzekchTK1GCXW" +
                "ki3DKGkZUEuaoaa60Kgw55Q5rt1eK7HKEG5npmR8aEod7BDLWy4CMTNAWR5iabCW" +
                "/KX28JbJL6Phau9j")), msRootCert} },
            {"id:41544D4C", new X509Certificate2[]{ // Atmel
                new X509Certificate2(Convert.FromBase64String(
                "MIICKzCCAdCgAwIBAgIUcD8hGhUZbtWr/R0SMo4rBkmgVHgwCgYIKoZIzj0EAwIw" +
                "czELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRvMRkwFwYDVQQHExBDb2xv" +
                "cmFkbyBTcHJpbmdzMQ4wDAYDVQQKEwVBdG1lbDEmMCQGA1UEAxMdQXRtZWwgVFBN" +
                "IFJvb3QgU2lnbmluZyBNb2R1bGUwHhcNMTAxMjMxMDAwMDAwWhcNNDAxMjMxMDAw" +
                "MDAwWjBzMQswCQYDVQQGEwJVUzERMA8GA1UECBMIQ29sb3JhZG8xGTAXBgNVBAcT" +
                "EENvbG9yYWRvIFNwcmluZ3MxDjAMBgNVBAoTBUF0bWVsMSYwJAYDVQQDEx1BdG1l" +
                "bCBUUE0gUm9vdCBTaWduaW5nIE1vZHVsZTBZMBMGByqGSM49AgEGCCqGSM49AwEH" +
                "A0IABH2Mc2ZzwulHWuF8a+EMpey51ZrMiF78oQywMFzGCmV4CmfpSQVpJqw23np8" +
                "QveCQOt7n/zsBMRsqk1bsAfYKwqjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB" +
                "Af8EBTADAQH/MB0GA1UdDgQWBBQx0F0Qba/k7RndCq/TW+oio3gcVzAKBggqhkjO" +
                "PQQDAgNJADBGAiEAyNu4sBDbRURcVGhKysdHGYidk5H2Bia+yo5mDryJ3hMCIQCs" +
                "lDkUE4T1jHHwzSxca6KCXzgtpyui78G742CdYm9W5Q==")), msRootCert} },
            //{"id:4252434D", "BRCM"},
            //{"id:48504500", "HPE"},
            //{"id:49424d00", "IBM"},
            {"id:49465800", // Infineon
                new X509Certificate2[]{
                new X509Certificate2(Convert.FromBase64String(
                "MIIEUDCCAzigAwIBAgIQRyQE4N8hgD99IM2HSOq5WjANBgkqhkiG9w0BAQUFADCB" +
                "ljELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMTswOQYDVQQL" +
                "EzJWZXJpU2lnbiBUcnVzdGVkIENvbXB1dGluZyBDZXJ0aWZpY2F0aW9uIEF1dGhv" +
                "cml0eTExMC8GA1UEAxMoVmVyaVNpZ24gVHJ1c3RlZCBQbGF0Zm9ybSBNb2R1bGUg" +
                "Um9vdCBDQTAeFw0wNTEwMjUwMDAwMDBaFw0zMDEwMjQyMzU5NTlaMG0xCzAJBgNV" +
                "BAYTAkRFMRAwDgYDVQQIEwdCYXZhcmlhMSEwHwYDVQQKExhJbmZpbmVvbiBUZWNo" +
                "bm9sb2dpZXMgQUcxDDAKBgNVBAsTA0FJTTEbMBkGA1UEAxMSSUZYIFRQTSBFSyBS" +
                "b290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1yZqFFg0PLDo" +
                "cW7Fyis2Xe5vERxnJ+KlEMUOQnrw5At9f0/ggovDM8uCVW71T6e24T6HH6kUQZCt" +
                "yddtsaf0tebmA3TxjiuBzBAtT6qyns35+sXuL6uZaLnjGKXDv+uByOzpmBXUSwq1" +
                "tdSTPQ0wWWQ6v/qwKofZdxAaPCTIBw61G08rkUT42a1hPESmVFrmc5hcnn4AQmJE" +
                "cjcOhClwIKE9OQw8TzI+7ncgCZlY3FZFKqHp7NRNnaihpmKbHvn5wXIUnKuvS4iZ" +
                "HqSbzGBuZ0ogqJ22ruDJi+JWYUWBmgI1JO85CPJ1Q58t0ME3hM3oWeqV6adWUcIc" +
                "IpclkYQWlwIDAQABo4HBMIG+MBIGA1UdEwEB/wQIMAYBAf8CAQEwWAYDVR0gAQH/" +
                "BE4wTDBKBgtghkgBhvhFAQcvATA7MDkGCCsGAQUFBwIBFi1odHRwOi8vd3d3LnZl" +
                "cmlzaWduLmNvbS9yZXBvc2l0b3J5L2luZGV4Lmh0bWwwDgYDVR0PAQH/BAQDAgIE" +
                "MB0GA1UdDgQWBBRW65FEhWPWcrOu1EWWC/eUDlRCpjAfBgNVHSMEGDAWgBQPFPXj" +
                "IIhEFsomv40fzjcV6kVvBjANBgkqhkiG9w0BAQUFAAOCAQEAWKL5zsV8p/TZk3mt" +
                "9m9NAqXWBDVHBnDgBE+Qphf25s+3s098vkWVLTddH3PtddF3MEYC4W8+dn4tyFe9" +
                "mQ+96q8dwJdNabwBokrZy2beL71CXt/4jYNN0j/N9uYO4vIDBFDKRMWCtUO217+w" +
                "xQTSOv5+mpgFw7UML/QpgpdmZy2i+eZPxDo8dzT+YJXC5vsHVSooA3rWDDzvnoLC" +
                "cmDDiT3pG6AdjAN61MeeHHmoJavV8Tvdoa3g14Sn1lL+TQ1xaznyh520sX0dXPTp" +
                "GqZbDzqEMiVbG7vFECqINE96/rwppJlWK91F1MZikGXr7FeF5C0JutGLb0gaYOmv" +
                "Yau4DQ==")),
                new X509Certificate2(Convert.FromBase64String(
                "MIIFqzCCA5OgAwIBAgIBAzANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJERTEh" +
                "MB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJPUFRJ" +
                "R0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkgUlNB" +
                "IFJvb3QgQ0EwHhcNMTMwNzI2MDAwMDAwWhcNNDMwNzI1MjM1OTU5WjB3MQswCQYD" +
                "VQQGEwJERTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYD" +
                "VQQLDBJPUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElH" +
                "QShUTSkgUlNBIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC" +
                "AQC7E+gc0B5T7awzux66zMMZMTtCkPqGv6a3NVx73ICg2DSwnipFwBiUl9soEodn" +
                "25SVVN7pqmvKA2gMTR5QexuYS9PPerfRZrBY00xyFx84V+mIRPg4YqUMLtZBcAwr" +
                "R3GO6cffHp20SBH5ITpuqKciwb0v5ueLdtZHYRPq1+jgy58IFY/vACyF/ccWZxUS" +
                "JRNSe4ruwBgI7NMWicxiiWQmz1fE3e0mUGQ1tu4M6MpZPxTZxWzN0mMz9noj1oIT" +
                "ZUnq/drN54LHzX45l+2b14f5FkvtcXxJ7OCkI7lmWIt8s5fE4HhixEgsR2RX5hzl" +
                "8XiHiS7uD3pQhBYSBN5IBbVWREex1IUat5eAOb9AXjnZ7ivxJKiY/BkOmrNgN8k2" +
                "7vOS4P81ix1GnXsjyHJ6mOtWRC9UHfvJcvM3U9tuU+3dRfib03NGxSPnKteL4SP1" +
                "bdHfiGjV3LIxzFHOfdjM2cvFJ6jXg5hwXCFSdsQm5e2BfT3dWDBSfR4h3Prpkl6d" +
                "cAyb3nNtMK3HR5yl6QBuJybw8afHT3KRbwvOHOCR0ZVJTszclEPcM3NQdwFlhqLS" +
                "ghIflaKSPv9yHTKeg2AB5q9JSG2nwSTrjDKRab225+zJ0yylH5NwxIBLaVHDyAEu" +
                "81af+wnm99oqgvJuDKSQGyLf6sCeuy81wQYO46yNa+xJwQIDAQABo0IwQDAdBgNV" +
                "HQ4EFgQU3LtWq/EY/KaadREQZYQSntVBkrkwDgYDVR0PAQH/BAQDAgAGMA8GA1Ud" +
                "EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAGHTBUx3ETIXYJsaAgb2pyyN" +
                "UltVL2bKzGMVSsnTCrXUU8hKrDQh3jNIMrS0d6dU/fGaGJvehxmmJfjaN/IFWA4M" +
                "BdZEnpAe2fJEP8vbLa/QHVfsAVuotLD6QWAqeaC2txpxkerveoV2JAwj1jrprT4y" +
                "rkS8SxZuKS05rYdlG30GjOKTq81amQtGf2NlNiM0lBB/SKTt0Uv5TK0jIWbz2WoZ" +
                "gGut7mF0md1rHRauWRcoHQdxWSQTCTtgoQzeBj4IS6N3QxQBKV9LL9UWm+CMIT7Y" +
                "np8bSJ8oW4UdpSuYWe1ZwSjZyzDiSzpuc4gTS6aHfMmEfoVwC8HN03/HD6B1Lwo2" +
                "DvEaqAxkya9IYWrDqkMrEErJO6cqx/vfIcfY/8JYmUJGTmvVlaODJTwYwov/2rjr" +
                "la5gR+xrTM7dq8bZimSQTO8h6cdL6u+3c8mGriCQkNZIZEac/Gdn+KwydaOZIcnf" +
                "Rdp3SalxsSp6cWwJGE4wpYKB2ClM2QF3yNQoTGNwMlpsxnU72ihDi/RxyaRTz9OR" +
                "pubNq8Wuq7jQUs5U00ryrMCZog1cxLzyfZwwCYh6O2CmbvMoydHNy5CU3ygxaLWv" +
                "JpgZVHN103npVMR3mLNa3QE+5MFlBlP3Mmystu8iVAKJas39VO5y5jad4dRLkwtM" +
                "6sJa8iBpdRjZrBp5sJBI")), msRootCert} },
            {"id:494E5443", new X509Certificate2[]{ //Intel
                new X509Certificate2(Convert.FromBase64String(
                "MIICdzCCAh6gAwIBAgIUB+dPf7a3IyJGO923z34oQLRP7pwwCgYIKoZIzj0EAwIw" +
                "gYcxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xh" +
                "cmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMSEwHwYDVQQLDBhUUE0gRUsg" +
                "cm9vdCBjZXJ0IHNpZ25pbmcxFjAUBgNVBAMMDXd3dy5pbnRlbC5jb20wHhcNMTQw" +
                "MTE1MDAwMDAwWhcNNDkxMjMxMjM1OTU5WjCBhzELMAkGA1UEBgwCVVMxCzAJBgNV" +
                "BAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEaMBgGA1UECgwRSW50ZWwgQ29y" +
                "cG9yYXRpb24xITAfBgNVBAsMGFRQTSBFSyByb290IGNlcnQgc2lnbmluZzEWMBQG" +
                "A1UEAwwNd3d3LmludGVsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJR9" +
                "gVEsjUrMb+E/dl19ywJsKZDnghmwVyG16dAfQ0Pftp1bjhtPEGEguvbLGRRopKWH" +
                "VscAOlTFnvCHq+6/9/SjZjBkMB8GA1UdIwQYMBaAFOhSBcJP2NLVpSFHFrbODHtb" +
                "uncPMB0GA1UdDgQWBBToUgXCT9jS1aUhRxa2zgx7W7p3DzASBgNVHRMBAf8ECDAG" +
                "AQH/AgEBMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNHADBEAiAldFScWQ6L" +
                "PQgW/YT+2GILcATEA2TgzASaCrG+AzL6FgIgLH8ABRzm028hRYR/JZVGkHiomzYX" +
                "VILmTjHwSL7uZBU=")), msRootCert} },
            //{"id:4C454E00", "LEN"},
            //{"id:4E534D20", "NSM"},
            {"id:4E545A00", new X509Certificate2[]{ // Nationz/NTZ
                new X509Certificate2(Convert.FromBase64String(
                "MIICRDCCAcqgAwIBAgIBATAKBggqhkjOPQQDAzBrMQswCQYDVQQGEwJDTjEhMB8G" + 
                "A1UECgwYTmF0aW9ueiBUZWNobm9sb2dpZXMgSW5jMRswGQYDVQQLDBJOYXRpb256" + 
                "IFRQTSBEZXZpY2UxHDAaBgNVBAMME05hdGlvbnogVFBNIFJvb3QgQ0EwHhcNMTcw" + 
                "NTEyMDAwMDAwWhcNNDcwNTEzMDAwMDAwWjBrMQswCQYDVQQGEwJDTjEhMB8GA1UE" + 
                "CgwYTmF0aW9ueiBUZWNobm9sb2dpZXMgSW5jMRswGQYDVQQLDBJOYXRpb256IFRQ" + 
                "TSBEZXZpY2UxHDAaBgNVBAMME05hdGlvbnogVFBNIFJvb3QgQ0EwdjAQBgcqhkjO" + 
                "PQIBBgUrgQQAIgNiAATvuDTN8TNvp3A9fSjWpDARLmvz7ItQrDq/mmuzvzInwQfs" + 
                "YKUUJza4MXB3yS0PH1jjv1YMvaIBIalAgc+kahScQUy6W2fy6hd36pazmc/vQfG3" + 
                "Gdhw56gGwRHx4rn4TuqjQjBAMB0GA1UdDgQWBBQ6vP8I314BDCtkB4vHzpUG9Aj9" + 
                "5DAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNo" + 
                "ADBlAjApzqSmd4cCMKC7slJ4NE/7zweXZx89JzSEnEWGcq78jbbXCw6yM+R4nCNX" + 
                "phflI9QCMQCeFOAvyR+DQvThfGFINABej+1zeDVIjuZHat3FHVyV0UQVClPgMlZu" + 
                "TntipXwGOVY=")), msRootCert } }, 
            {"id:4E544300", new X509Certificate2[]{ // Nuvoton Technology / NTC
                new X509Certificate2(Convert.FromBase64String(
                "MIIDSjCCAjKgAwIBAgIGAK3jXfbVMA0GCSqGSIb3DQEBBQUAMFIxUDAcBgNVBAMT" +
                "FU5UQyBUUE0gRUsgUm9vdCBDQSAwMTAlBgNVBAoTHk51dm90b24gVGVjaG5vbG9n" +
                "eSBDb3Jwb3JhdGlvbjAJBgNVBAYTAlRXMB4XDTEyMDcxMTE2MjkzMFoXDTMyMDcx" +
                "MTE2MjkzMFowUjFQMBwGA1UEAxMVTlRDIFRQTSBFSyBSb290IENBIDAxMCUGA1UE" +
                "ChMeTnV2b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwggEi" +
                "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDoNqxhtD4yUtXhqKQGGZemoKJy" +
                "uj1RnWvmNgzItLeejNU8B6fOnpMQyoS4K72tMhhFRK2jV9RYzyJMSjEwyX0ASTO1" +
                "2yMti2UJQS60d36eGwk8WLgrFnnITlemshi01h9t1MOmay3TO1LLH/3/VDKJ+jbd" +
                "cbfIO2bBquN8r3/ojYUaNSPj6pK1mmsMoJXF4dGRSEwb/4ozBIw5dugm1MEq4Zj3" +
                "GZ0YPg5wyLRugQbt7DkUOX4FGuK5p/C0u5zX8u33EGTrDrRz3ye3zO+aAY1xXF/m" +
                "qwEqgxX5M8f0/DXTTO/CfeIksuPeOzujFtXfi5Cy64eeIZ0nAUG3jbtnGjoFAgMB" +
                "AAGjJjAkMA4GA1UdDwEB/wQEAwICBDASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqG" +
                "SIb3DQEBBQUAA4IBAQBBQznOPJAsD4Yvyt/hXtVJSgBX/+rRfoaqbdt3UMbUPJYi" +
                "pUoTUgaTx02DVRwommO+hLx7CS++1F2zorWC8qQyvNbg7iffQbbjWitt8NPE6kCr" +
                "q0Y5g7M/LkQDd5N3cFfC15uFJOtlj+A2DGzir8dlXU/0qNq9dBFbi+y+Y3rAT+wK" +
                "fktmN82UT861wTUzDvnXO+v7H5DYXjUU8kejPW6q+GgsccIbVTOdHNNWbMrcD9yf" +
                "oS91nMZ/+/n7IfFWXNN82qERsrvOFCDsbIzUOR30N0IP++oqGfwAbKFfCOCFUz6j" +
                "jpXUdJlh22tp12UMsreibmi5bsWYBgybwSbRgvzE")),
                new X509Certificate2(Convert.FromBase64String(
                "MIIDSjCCAjKgAwIBAgIGAPadBmPZMA0GCSqGSIb3DQEBBQUAMFIxUDAcBgNVBAMT" +
                "FU5UQyBUUE0gRUsgUm9vdCBDQSAwMjAlBgNVBAoTHk51dm90b24gVGVjaG5vbG9n" +
                "eSBDb3Jwb3JhdGlvbjAJBgNVBAYTAlRXMB4XDTEyMDcxMTE2MzMyNFoXDTMyMDcx" +
                "MTE2MzMyNFowUjFQMBwGA1UEAxMVTlRDIFRQTSBFSyBSb290IENBIDAyMCUGA1UE" +
                "ChMeTnV2b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwggEi" +
                "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSagWxaANT1YA2YUSN7sq7yzOT" +
                "1ymbIM+WijhE5AGcLwLFoJ9fmaQrYL6fAW2EW/Q3yu97Q9Ysr8yYZ2XCCfxfseEr" +
                "Vs80an8Nk6LkTDz8+0Hm0Cct0klvNUAZEIvWpmgHZMvGijXyOcp4z494d8B28Ynb" +
                "I7x0JMXZZQQKQi+WfuHtntF+2osYScweocipPrGeONLKU9sngWZ2vnnvw1SBneTa" +
                "irxq0Q0SD6Bx9jtxvdf87euk8JzfPhX8jp8GEeAjmLwGR+tnOQrDmczGNmp7YYNN" +
                "R+Q7NZVoYWHw5jaoZnNxbouWUXZZxFqDsB/ndCKWtsIzRYPuWcqrFcmUN4SVAgMB" +
                "AAGjJjAkMA4GA1UdDwEB/wQEAwICBDASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqG" +
                "SIb3DQEBBQUAA4IBAQAIkdDSErzPLPYrVthw4lKjW4tRYelUicMPEHKjQeVUAAS5" +
                "y9XTzB4DWISDAFsgtQjqHJj0xCG+vpY0Rmn2FCO/0YpP+YBQkdbJOsiyXCdFy9e4" +
                "gGjQ24gw1B+rr84+pkI51y952NYBdoQDeb7diPe+24U94f//DYt/JQ8cJua4alr3" +
                "2Pohhh5TxCXXfU2EHt67KyqBSxCSy9m4OkCOGLHL2X5nQIdXVj178mw6DSAwyhwR" +
                "n3uJo5MvUEoQTFZJKGSXfab619mIgzEr+YHsIQToqf44VfDMDdM+MFiXQ3a5fLii" +
                "hEKQ9DhBPtpHAbhFA4jhCiG9HA8FdEplJ+M4uxNz")),
                new X509Certificate2(Convert.FromBase64String(
                "MIIDWTCCAkGgAwIBAgIJAMklAEG4bgQ6MA0GCSqGSIb3DQEBBQUAMFgxVjAiBgNV" +
                "BAMTG05UQyBUUE0gRUsgUm9vdCBDQSBBUlNVRiAwMTAlBgNVBAoTHk51dm90b24g" +
                "VGVjaG5vbG9neSBDb3Jwb3JhdGlvbjAJBgNVBAYTAlRXMB4XDTE0MDQwMTE4MzQz" +
                "OFoXDTM0MDMyODE4MzQzOFowWDFWMCIGA1UEAxMbTlRDIFRQTSBFSyBSb290IENB" +
                "IEFSU1VGIDAxMCUGA1UEChMeTnV2b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9u" +
                "MAkGA1UEBhMCVFcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCxcfP" +
                "yaNsGhaR28qqisqkrb4Z2OPul7BRNlIEYP8jSFORygyfp4j7bKRyVTTONCUbPq+J" +
                "/a4yRcdbEs8dzvzXypQbVUjuC4sOKjPiWLfOhj1Z1yvOn19Xe3Ei4UzMKJm+xpb1" +
                "BYR4YfrnuVzL4do/B/lCr2AYs4Fmtn1uzXBp1St8TRJz9HTW1yKJ2ZOqTgW3DX80" +
                "6DP//3kIatTuLCZ6Zsdl6fsgMPxJGwrI35ThKBtaUMT93abb/KB/dugvoIgtEi9D" +
                "GEC2C0UWsvJEfu0Qi8zoxtYvd9Y2tRlMxMhK75uShXHxRcG+WOGEnm6uVpGphLKg" +
                "qxAl1tuFcb94vi7dAgMBAAGjJjAkMA4GA1UdDwEB/wQEAwICBDASBgNVHRMBAf8E" +
                "CDAGAQH/AgEAMA0GCSqGSIb3DQEBBQUAA4IBAQB7epeKy2Sa+9huMzK4PnIpjiaX" +
                "QrxPx+E8BVGw6VuQqTcTPQRvPhNpc4VF/6/7MA9qb6vDxWEf40tqNi8e/RPNlRFY" +
                "Dh4tQ1Hhl69NrZVYZeXl1cU/ometoAAbz79ugq78iFndJ5rHMQ85GRwtW9i/q0p1" +
                "VjJ8dLYJ7aRBDTP3hndc35GmZg3q1UX93WD6mM5KuE+mOdv7MXKMtYSrV+dE/iGM" +
                "ASrratJf57P6N8BpegPQaSb6UnElwBpwhRxzW7N9qgjQWIqrxe97CfJk41RvtnKu" +
                "SePqlm1PtWkygt9bYaInLZYkcknXTD/7BtzAyyS25HtG/YTvuMtKItCp7Z4n")),
                new X509Certificate2(Convert.FromBase64String(
                "MIIDkjCCAnqgAwIBAgIISN0JfIK6vE0wDQYJKoZIhvcNAQEFBQAwVTFTMB8GA1UE" +
                "AxMYTnV2b3RvbiBUUE0gUm9vdCBDQSAxMDEzMCUGA1UEChMeTnV2b3RvbiBUZWNo" +
                "bm9sb2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwHhcNMTUwNTExMDg0MzI1WhcN" +
                "MzUwNTA3MDg0MzI1WjBVMVMwHwYDVQQDExhOdXZvdG9uIFRQTSBSb290IENBIDEw" +
                "MTMwJQYDVQQKEx5OdXZvdG9uIFRlY2hub2xvZ3kgQ29ycG9yYXRpb24wCQYDVQQG" +
                "EwJUVzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDAta6EZBlhF1MC" +
                "Z9GeMXqw8puwZEDI3qR/rwGhEUj2oqhFY/K9zUk2YQCkC6X5lrr/lbWfvZtUGMFC" +
                "P4VQlt+bGPTOladGg6zJ/7a6yCd9MqkZbw92niDNhWcXsiB7SRyHYdr/He8tNOoD" +
                "mVdNFXxknP8QH3soBPahxckqtrhhk+24Iran04jOAc0959VnP8H0Jyg4BjehIQjj" +
                "BGGK+bJWZXHYRFlDj4dRW+epChdOqTpWOulf5GOvwNm3sv4ojU2fJ8cA5TznX81z" +
                "+Se6hmw/RF8rUGjf1uiKbsxnbIf3An01mZYgD98FXEHAWAW92vAJUuEQJVBlTest" +
                "1YmsaT0CAwEAAaNmMGQwDgYDVR0PAQH/BAQDAgIEMBIGA1UdEwEB/wQIMAYBAf8C" +
                "AQAwHwYDVR0jBBgwFoAUoNc3KQ4WzyrivucQDPVrLwTF8EMwHQYDVR0OBBYEFKDX" +
                "NykOFs8q4r7nEAz1ay8ExfBDMA0GCSqGSIb3DQEBBQUAA4IBAQCOXMzQYz3vr9tg" +
                "SiFr6qha2+Jay+EK0iLjSKvNzcTv5yaO8I6pb7tdocvze8394PtM42d2OTOM99lJ" +
                "bZogquaJ6fLHMwzO7UEGndtm6YMp6APXk4ecRqUDLqofIWL6PQUVwSEYlAC6RM9k" +
                "n4MJqckIxsc6iC38lsjyn4ut8o/E3fIo8UzYDl2P+KK1VkjDcmmgNf6seHmBsOYC" +
                "vOc4xYpq0yWuZFfxeyC4wC4mOAKLZX2yLMYrYBmnDd60nc0hgI1/TKb1H/Ew2P7R" +
                "UxEDMGe8e3A9YR4M/09FLn8cTTjq7hflRlcqiarpPo6+9Z3dqzmqTQxvVQ/DIVqE" +
                "3r3WOnnr")),
                new X509Certificate2(Convert.FromBase64String(
                "MIICBjCCAaygAwIBAgIIEDiqn2SaqGMwCgYIKoZIzj0EAwIwVTFTMB8GA1UEAxMY" +
                "TnV2b3RvbiBUUE0gUm9vdCBDQSAxMTEwMCUGA1UEChMeTnV2b3RvbiBUZWNobm9s" +
                "b2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwHhcNMTUwNTExMDg0MzMzWhcNMzUw" +
                "NTA3MDg0MzMzWjBVMVMwHwYDVQQDExhOdXZvdG9uIFRQTSBSb290IENBIDExMTAw" +
                "JQYDVQQKEx5OdXZvdG9uIFRlY2hub2xvZ3kgQ29ycG9yYXRpb24wCQYDVQQGEwJU" +
                "VzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDVkEOpuyhuviaDH6xQj3faaV2Z4" +
                "FvXSdwUkTiB1JjPDgv1PU0SFYtEE1W9VmI1GcOn5FAUi2/QM36DPhmPTd+qjZjBk" +
                "MA4GA1UdDwEB/wQEAwICBDASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBQV" +
                "kdS26vmNAQSGS2kDpI3QAmB30zAfBgNVHSMEGDAWgBQVkdS26vmNAQSGS2kDpI3Q" +
                "AmB30zAKBggqhkjOPQQDAgNIADBFAiEAlfxysfHDcxYDed5dmRbvHPKHLEEq9Y9P" +
                "wAxoKqH7Q5kCIGfsxiLr2j9nJ9jELwXz0/VWN9PhUNdM3qmsx2JEne6p")),
                new X509Certificate2(Convert.FromBase64String(
                "MIIDkjCCAnqgAwIBAgIIWAnP9p2CIZcwDQYJKoZIhvcNAQEFBQAwVTFTMB8GA1UE" +
                "AxMYTnV2b3RvbiBUUE0gUm9vdCBDQSAyMDEwMCUGA1UEChMeTnV2b3RvbiBUZWNo" +
                "bm9sb2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwHhcNMTUwNDIzMDY1OTE5WhcN" +
                "MzUwNDE5MDY1OTE5WjBVMVMwHwYDVQQDExhOdXZvdG9uIFRQTSBSb290IENBIDIw" +
                "MTAwJQYDVQQKEx5OdXZvdG9uIFRlY2hub2xvZ3kgQ29ycG9yYXRpb24wCQYDVQQG" +
                "EwJUVzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKcE9saVURE582ny" +
                "dHsZO7+3xmdMFbOPCdplBda/EJg9cg7n6bZ79Qv7hyymN5qE23SOPNFvm8SAdmCJ" +
                "ybmTnk1y+SyiDw5gUpckbXsRYAetTwqtdfBkF4TkFoRJDIraQC8miTdYqXMXfWTo" +
                "bhHXf/oV953laOCO/SRlqXzAWzm5d8PwixUBLZTnvcgxM+pXwv6JY6wgXpv55fY1" +
                "D3M1hyiNALib+rg0LwazalU0DOryAAIqFzMgkR2IaefkAmpmQ1xpfMJsK+BMixcI" +
                "XUCzSGGKKdkc3WUDye/vsyXYQ5zoYuLt3xb7BEZxes31lqbs1gniNz4oD5ptmrS4" +
                "8V7Rz/kCAwEAAaNmMGQwDgYDVR0PAQH/BAQDAgIEMBIGA1UdEwEB/wQIMAYBAf8C" +
                "AQAwHwYDVR0jBBgwFoAUCDAPQ6j0uMjmJKT3Bgz1nnRQFecwHQYDVR0OBBYEFAgw" +
                "D0Oo9LjI5iSk9wYM9Z50UBXnMA0GCSqGSIb3DQEBBQUAA4IBAQAE0pMnjz5o3QUd" +
                "S3lLQn3+vXkS2xc1EmPxcVFxjPbrJDtnNRMWwglC8zo70VgWu/+ulwzy783zJSiT" +
                "nkWPeuszqp3xOtCPWDE4D2sxVbWH3pvel2tgZJv0KJsJH93QE53WbHUwSn2JjHNH" +
                "UJiBpq0genUxGD+zBI3NGDGB1iti66aJfCdjn8C0G0gTmQ8jFpZ6AsX1GSvPYeU6" +
                "EqN9ynIEYUVcRKwoHQaSmqDd7HVp97fwD+mkOfFYByLVUqC09rNFW81Va4Ze2gw2" +
                "HiKz/SVSA5mA/91wfEZSZ6azOgDZNQlbgBo27mZFJ5mR7iJbWgtD+vO4+wRZK8Bc" +
                "8yWxV8ri")),
                new X509Certificate2(Convert.FromBase64String(
                "MIICBjCCAaygAwIBAgIIP5MvnZk8FrswCgYIKoZIzj0EAwIwVTFTMB8GA1UEAxMY" +
                "TnV2b3RvbiBUUE0gUm9vdCBDQSAyMTEwMCUGA1UEChMeTnV2b3RvbiBUZWNobm9s" +
                "b2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwHhcNMTUxMDE5MDQzMjAwWhcNMzUx" +
                "MDE1MDQzMjAwWjBVMVMwHwYDVQQDExhOdXZvdG9uIFRQTSBSb290IENBIDIxMTAw" +
                "JQYDVQQKEx5OdXZvdG9uIFRlY2hub2xvZ3kgQ29ycG9yYXRpb24wCQYDVQQGEwJU" +
                "VzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPv9uK2BNm8/nmIyNsc2/aKHV0WR" +
                "ptzge3jKAIgUMosQIokl4LE3iopXWD3Hruxjf9vkLMDJrTeK3hWh2ySS4ySjZjBk" +
                "MA4GA1UdDwEB/wQEAwICBDASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSf" +
                "u3mqD1JieL7RUJKacXHpajW+9zAfBgNVHSMEGDAWgBSfu3mqD1JieL7RUJKacXHp" +
                "ajW+9zAKBggqhkjOPQQDAgNIADBFAiEA/jiywhOKpiMOUnTfDmXsXfDFokhKVNTX" +
                "B6Xtqm7J8L4CICjT3/Y+rrSnf8zrBXqWeHDh8Wi41+w2ppq6Ev9orZFI")), msRootCert} },
            {"id:51434F4D", new X509Certificate2[] { msRootCert } }, // QCOM
            //{"id:534D5343", "SMSC"},
            {"id:53544D20", new X509Certificate2[]{ // ST Microelectronics
                new X509Certificate2(Convert.FromBase64String(
                "MIID1zCCAr+gAwIBAgILBAAAAAABIBkJGa4wDQYJKoZIhvcNAQELBQAwgYcxOzA5" +
                "BgNVBAsTMkdsb2JhbFNpZ24gVHJ1c3RlZCBDb21wdXRpbmcgQ2VydGlmaWNhdGUg" +
                "QXV0aG9yaXR5MRMwEQYDVQQKEwpHbG9iYWxTaWduMTMwMQYDVQQDEypHbG9iYWxT" +
                "aWduIFRydXN0ZWQgUGxhdGZvcm0gTW9kdWxlIFJvb3QgQ0EwHhcNMDkwMzE4MTAw" +
                "MDAwWhcNNDkwMzE4MTAwMDAwWjCBhzE7MDkGA1UECxMyR2xvYmFsU2lnbiBUcnVz" +
                "dGVkIENvbXB1dGluZyBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxEzARBgNVBAoTCkds" +
                "b2JhbFNpZ24xMzAxBgNVBAMTKkdsb2JhbFNpZ24gVHJ1c3RlZCBQbGF0Zm9ybSBN" +
                "b2R1bGUgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPi3" +
                "Gi0wHyTT7dq24caFAp31gXFDvALRGJrMiP+TunIYPacYD8eBVSNEiVoCUcVfYxzl" +
                "/DPTxmRyGXgQM8CVh9THrxDTW7N2PSAoZ7fvlmjTiBL/IQ7m1F+9wGI/FuaMTphz" +
                "w6lBda7HFlIYKTbM/vz24axCHLzJ8Xir2L889D9MMIerBRqouVsDGauH+TIOdw4o" +
                "IGKhorqfsDro57JHwViMWlbB1Ogad7PBX5X/e9GDNdZTdo4c0bZnKO+dEtzEgKCh" +
                "JmQ53Mxa9y4xPMGRRnjLsyxuM99vkkYXy7rnxctSo7GtGIJJVabNuXZ0peaY9ku0" +
                "CUgKAsQndLkTHz8bIh0CAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB" +
                "/wQFMAMBAf8wHQYDVR0OBBYEFB4jY/CFtfYlTu0awFC+ZXzH1BV6MA0GCSqGSIb3" +
                "DQEBCwUAA4IBAQCVb7lI4d49u7EtCX03/rUCCiaZ64NMxxqRmcSVdUx6yRrbl8NN" +
                "FNr6ym2kTvwe1+JkTCiDxKzJsOR/jcPczAFiYpFbZQYLA6RK0bzbL9RGcaw5LLhY" +
                "o/flqsu3N2/HNesWbekoxLosP6NLGEOnpj1B+R3y7HCQq/08U5l3Ete6TRKTAavc" +
                "0mty+uCFtLXf+tirl7xSaIGD0LwcYNdzLEB9g4je6FQSWL0QOXb+zR755QYupZAw" +
                "G1PnOgYWfqWowKcQQexFPrKGlzh0ncITV/nBEi++fnnZ7TFiwaKwe+WussrROV1S" +
                "DDF29dmoMcbSFDL+DgSMabVT6Qr6Ze1rbmSh")),
                new X509Certificate2(Convert.FromBase64String(
                "MIICszCCAjqgAwIBAgIORdycjBUV21nQRkudeekwCgYIKoZIzj0EAwMwgYsxOzA5" +
                "BgNVBAsTMkdsb2JhbFNpZ24gVHJ1c3RlZCBDb21wdXRpbmcgQ2VydGlmaWNhdGUg" +
                "QXV0aG9yaXR5MRMwEQYDVQQKEwpHbG9iYWxTaWduMTcwNQYDVQQDEy5HbG9iYWxT" +
                "aWduIFRydXN0ZWQgUGxhdGZvcm0gTW9kdWxlIEVDQyBSb290IENBMB4XDTE0MTEy" +
                "NjAwMDAwMFoXDTM4MDExOTAzMTQwN1owgYsxOzA5BgNVBAsTMkdsb2JhbFNpZ24g" +
                "VHJ1c3RlZCBDb21wdXRpbmcgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRMwEQYDVQQK" +
                "EwpHbG9iYWxTaWduMTcwNQYDVQQDEy5HbG9iYWxTaWduIFRydXN0ZWQgUGxhdGZv" +
                "cm0gTW9kdWxlIEVDQyBSb290IENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAENTps" +
                "86FDUD+bep3kd1U5pnita316zBktOVNWxZQ+Ymua0oaR66ItzHrl19zYSGbW6ar0" +
                "1V91kktxWDJ6UFl3MyH3yXKsCHS2O5vxMlfmdRp8tpebMorHtIWf9u1+ctNFo2Mw" +
                "YTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUYT78" +
                "EZkKf7CpW5CgJl4pYUe3MAMwHwYDVR0jBBgwFoAUYT78EZkKf7CpW5CgJl4pYUe3" +
                "MAMwCgYIKoZIzj0EAwMDZwAwZAIwd02iAb5aN/pQGWdTJ7/lgMhFCuOLGtQ+ocdV" +
                "/xmoxdIWLtggAuq9fFDfsu/vzeJ7AjAGhdk03AjHpLl0dAp7aCI8D8qupwyYTBaL" +
                "rSJCZDMHhvNhETbbLu8uEPKt/U6/mGM=")),
                new X509Certificate2(Convert.FromBase64String(
                "MIIEDDCCAvSgAwIBAgILBAAAAAABIsFs834wDQYJKoZIhvcNAQELBQAwgYcxOzA5" +
                "BgNVBAsTMkdsb2JhbFNpZ24gVHJ1c3RlZCBDb21wdXRpbmcgQ2VydGlmaWNhdGUg" +
                "QXV0aG9yaXR5MRMwEQYDVQQKEwpHbG9iYWxTaWduMTMwMQYDVQQDEypHbG9iYWxT" +
                "aWduIFRydXN0ZWQgUGxhdGZvcm0gTW9kdWxlIFJvb3QgQ0EwHhcNMDkwNzI4MTIw" +
                "MDAwWhcNMzkxMjMxMjM1OTU5WjBKMQswCQYDVQQGEwJDSDEeMBwGA1UEChMVU1RN" +
                "aWNyb2VsZWN0cm9uaWNzIE5WMRswGQYDVQQDExJTVE0gVFBNIEVLIFJvb3QgQ0Ew" +
                "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDxBLG5wcB9J0MsiJMreoWQ" +
                "l21bBN12SSGZPJ3HoPjzcrzAz6SPy+TrFmZ6eUVspsFL/23wdPprqTUtDHi+C2pw" +
                "k/3dF3/Rb2t/yHgiPlbCshYpi5f/rJ7nzbQ1ca2LzX3saBe53VfNQQV0zd5uM0DT" +
                "SrmAKU1RIAj2WlZFWXoN4NWTyRtqT5suPHa2y8FlCWMZKlS0FiY4pfM20b5YQ+EL" +
                "4zqb9zN53u/TdYZegrfSlc30Nl9G13Mgi+8rtPFKwsxx05EBbhVroH7aKVI1djsf" +
                "E1MVrUzw62PHik3xlzznXML8OjY//xKeiCWcsApuGCaIAf7TsTRi2l8DNB3rCr1X" +
                "AgMBAAGjgbQwgbEwDgYDVR0PAQH/BAQDAgIEMBIGA1UdEwEB/wQIMAYBAf8CAQEw" +
                "HQYDVR0OBBYEFG/mxWwHt2yLCoGSg1zLQR72jtEnMEsGA1UdIAREMEIwQAYJKwYB" +
                "BAGgMgFaMDMwMQYIKwYBBQUHAgEWJWh0dHA6Ly93d3cuZ2xvYmFsc2lnbi5uZXQv" +
                "cmVwb3NpdG9yeS8wHwYDVR0jBBgwFoAUHiNj8IW19iVO7RrAUL5lfMfUFXowDQYJ" +
                "KoZIhvcNAQELBQADggEBAFrKpwFmRh7BGdpPZWc1Y6wIbdTAF6T+q1KwDJcyAjgJ" +
                "qThFp3xTAt3tvyVrCRf7T/YARYE24DNa0iFaXsIXeQASDYHJjAZ6LQTslYBeRYLb" +
                "C9v8ZE2ocKSCiC8ALYlJWk39Wob0H1Lk6l2zcUo3oKczGiAcRrlmwV496wvGyted" +
                "2RBcLZro7yhOOGr9KMabV14fNl0lG+31J1nWI2hgTqh53GXg1QH2YpggD3b7UbVm" +
                "c6GZaX37N3z15XfQafuAfHt10kYCNdePzC9tOwirHIsO8lrxoNlzOSxX8SqQGbBI" +
                "+kWoe5+SY3gdOGGDQKIdw3W1poMN8bQ5x7XFcgVMwVU=")),
                new X509Certificate2(Convert.FromBase64String(
                "MIICyDCCAk+gAwIBAgIORyzLp/OdsAvb9r+66LowCgYIKoZIzj0EAwMwgYsxOzA5" +
                "BgNVBAsTMkdsb2JhbFNpZ24gVHJ1c3RlZCBDb21wdXRpbmcgQ2VydGlmaWNhdGUg" +
                "QXV0aG9yaXR5MRMwEQYDVQQKEwpHbG9iYWxTaWduMTcwNQYDVQQDEy5HbG9iYWxT" +
                "aWduIFRydXN0ZWQgUGxhdGZvcm0gTW9kdWxlIEVDQyBSb290IENBMB4XDTE1MTAy" +
                "ODAwMDAwMFoXDTM4MDExOTAzMTQwN1owTjELMAkGA1UEBhMCQ0gxHjAcBgNVBAoT" +
                "FVNUTWljcm9lbGVjdHJvbmljcyBOVjEfMB0GA1UEAxMWU1RNIFRQTSBFQ0MgUm9v" +
                "dCBDQSAwMTB2MBAGByqGSM49AgEGBSuBBAAiA2IABG7/OLXMiprQQHwNnkpT6aqG" +
                "zOGLcbbAgUtyjlXOZtuv0GB0ttJ6fwMwgFtt8RKlko8Bwn89/BoZOUcI4ne8ddRS" +
                "oqE6StnU3I13qqjalToq3Rnz61Omn6NErK1pxUe3j6OBtTCBsjAOBgNVHQ8BAf8E" +
                "BAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUIJJWPAtDqAVyUwMp" +
                "BxwH4OvsAwQwHwYDVR0jBBgwFoAUYT78EZkKf7CpW5CgJl4pYUe3MAMwTAYDVR0g" +
                "BEUwQzBBBgkrBgEEAaAyAVowNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xv" +
                "YmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCgYIKoZIzj0EAwMDZwAwZAIwWnuUAzwy" +
                "vHUhHehymKTZ2QcPUwHX0LdcVTac4ohyEL3zcuv/dM0BN62kFxHgBOhWAjAIxt9i" +
                "50yAxy0Z/MeV2NTXqKpLwdhWNuzOSFZnzRKsh9MxY3zj8nebDNlHTDGSMR0=")), msRootCert} },
            //{"id:534D534E", "SMSN"},
            //{"id:534E5300", "SNS"},
            //{"id:54584E00", "TXN"},
            {"id:57454300", new X509Certificate2[] { msRootCert } } // WEC
            //{"id:524F4343", "ROCC"},
            //{"id:474F4F47", "GOOG"}
    };
        public override void Verify()
        {
            if (null == Sig || CBORType.ByteString != Sig.Type || 0 == Sig.GetByteString().Length)
                throw new Fido2VerificationException("Invalid TPM attestation signature");

            if ("2.0" != attStmt["ver"].AsString())
                throw new Fido2VerificationException("FIDO2 only supports TPM 2.0");

            // Verify that the public key specified by the parameters and unique fields of pubArea
            // is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData
            PubArea pubArea = null;
            if (null != attStmt["pubArea"] &&
                CBORType.ByteString == attStmt["pubArea"].Type &&
                0 != attStmt["pubArea"].GetByteString().Length)
            { 
                pubArea = new PubArea(attStmt["pubArea"].GetByteString());
            }

            if (null == pubArea || null == pubArea.Unique || 0 == pubArea.Unique.Length)
                throw new Fido2VerificationException("Missing or malformed pubArea");

            var coseKty = CredentialPublicKey[CBORObject.FromObject(COSE.KeyCommonParameter.KeyType)].AsInt32();
            if (3 == coseKty) // RSA
            {
                var coseMod = CredentialPublicKey[CBORObject.FromObject(COSE.KeyTypeParameter.N)].GetByteString(); // modulus 
                var coseExp = CredentialPublicKey[CBORObject.FromObject(COSE.KeyTypeParameter.E)].GetByteString(); // exponent

                if (!coseMod.ToArray().SequenceEqual(pubArea.Unique.ToArray()))
                    throw new Fido2VerificationException("Public key mismatch between pubArea and credentialPublicKey");
                if ((coseExp[0] + (coseExp[1] << 8) + (coseExp[2] << 16)) != pubArea.Exponent)
                    throw new Fido2VerificationException("Public key exponent mismatch between pubArea and credentialPublicKey");
            }
            else if (2 == coseKty) // ECC
            {
                var curve = CredentialPublicKey[CBORObject.FromObject(COSE.KeyTypeParameter.Crv)].AsInt32();
                var X = CredentialPublicKey[CBORObject.FromObject(COSE.KeyTypeParameter.X)].GetByteString();
                var Y = CredentialPublicKey[CBORObject.FromObject(COSE.KeyTypeParameter.Y)].GetByteString();

                if (pubArea.EccCurve != CoseCurveToTpm[curve])
                    throw new Fido2VerificationException("Curve mismatch between pubArea and credentialPublicKey");
                if (!pubArea.ECPoint.X.SequenceEqual(X))
                    throw new Fido2VerificationException("X-coordinate mismatch between pubArea and credentialPublicKey");
                if (!pubArea.ECPoint.Y.SequenceEqual(Y))
                    throw new Fido2VerificationException("Y-coordinate mismatch between pubArea and credentialPublicKey");
            }
            // Concatenate authenticatorData and clientDataHash to form attToBeSigned.
            // see data variable

            // Validate that certInfo is valid
            CertInfo certInfo = null;
            if (null != attStmt["certInfo"] &&
                CBORType.ByteString == attStmt["certInfo"].Type &&
                0 != attStmt["certInfo"].GetByteString().Length)
            { 
                certInfo = new CertInfo(attStmt["certInfo"].GetByteString());
            }

            if (null == certInfo)
                throw new Fido2VerificationException("CertInfo invalid parsing TPM format attStmt");

            // Verify that magic is set to TPM_GENERATED_VALUE and type is set to TPM_ST_ATTEST_CERTIFY 
            // handled in parser, see CertInfo.Magic

            // Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg"
            if (null == Alg || CBORType.Number != Alg.Type || false == CryptoUtils.algMap.ContainsKey(Alg.AsInt32()))
                throw new Fido2VerificationException("Invalid TPM attestation algorithm");
            using(var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[Alg.AsInt32()]))
            {
                if (!hasher.ComputeHash(Data).SequenceEqual(certInfo.ExtraData)) 
                    throw new Fido2VerificationException("Hash value mismatch extraData and attToBeSigned");
            }

            // Verify that attested contains a TPMS_CERTIFY_INFO structure, whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea 
            using(var hasher = CryptoUtils.GetHasher(CryptoUtils.algMap[certInfo.Alg]))
            {
                if (false == hasher.ComputeHash(pubArea.Raw).SequenceEqual(certInfo.AttestedName))
                    throw new Fido2VerificationException("Hash value mismatch attested and pubArea");
            }

            // If x5c is present, this indicates that the attestation type is not ECDAA
            if (null != X5c && CBORType.Array == X5c.Type && 0 != X5c.Count)
            {
                if (null == X5c.Values || 0 == X5c.Values.Count ||
                    CBORType.ByteString != X5c.Values.First().Type ||
                    0 == X5c.Values.First().GetByteString().Length)
                {
                    throw new Fido2VerificationException("Malformed x5c in TPM attestation");
                }

                // Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
                var aikCert = new X509Certificate2(X5c.Values.First().GetByteString());

                var cpk = new CredentialPublicKey(aikCert, Alg.AsInt32());
                if (true != cpk.Verify(certInfo.Raw, Sig.GetByteString()))
                    throw new Fido2VerificationException("Bad signature in TPM with aikCert");

                // Verify that aikCert meets the TPM attestation statement certificate requirements
                // https://www.w3.org/TR/webauthn/#tpm-cert-requirements
                // Version MUST be set to 3
                if (3 != aikCert.Version)
                    throw new Fido2VerificationException("aikCert must be V3");

                // Subject field MUST be set to empty - they actually mean subject name
                if (0 != aikCert.SubjectName.Name.Length)
                    throw new Fido2VerificationException("aikCert subject must be empty");

                // The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
                // https://www.w3.org/TR/webauthn/#tpm-cert-requirements
                var SAN = SANFromAttnCertExts(aikCert.Extensions);
                if (null == SAN || 0 == SAN.Length)
                    throw new Fido2VerificationException("SAN missing from TPM attestation certificate");

                // From https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
                // "The issuer MUST include TPM manufacturer, TPM part number and TPM firmware version, using the directoryName 
                // form within the GeneralName structure. The ASN.1 encoding is specified in section 3.1.2 TPM Device 
                // Attributes. In accordance with RFC 5280[11], this extension MUST be critical if subject is empty 
                // and SHOULD be non-critical if subject is non-empty"

                // AsnEncodedData does this for us on Windows
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    SAN = SAN.Replace("2.23.133.2.1", "TPMManufacturer")
                        .Replace("2.23.133.2.2", "TPMModel")
                        .Replace("2.23.133.2.3", "TPMVersion");
                }
                // Best I can figure to do for now?
                if (false == SAN.Contains("TPMManufacturer") ||
                    false == SAN.Contains("TPMModel") ||
                    false == SAN.Contains("TPMVersion"))
                {
                    throw new Fido2VerificationException("SAN missing TPMManufacturer, TPMModel, or TPMVersion from TPM attestation certificate");
                }
                var tpmManufacturer = SAN.Substring(SAN.IndexOf("TPMManufacturer"), 27).Split('=').Last();
                if (false == TPMManufacturerRootMap.ContainsKey(tpmManufacturer))
                    throw new Fido2VerificationException("Invalid TPM manufacturer found parsing TPM attestation");
                var tpmRoots = TPMManufacturerRootMap[tpmManufacturer];
                var valid = false;
                var i = 0;
                while (valid == false && i < tpmRoots.Length)
                {
                    var chain = new X509Chain();
                    chain.ChainPolicy.ExtraStore.Add(tpmRoots[i]);
                    
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    if (tpmManufacturer == "id:FFFFF1D0")
                    {
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority | X509VerificationFlags.IgnoreInvalidBasicConstraints;
                    }
                    else
                    {
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                    }
                    if (X5c.Values.Count > 1)
                    {
                        foreach (var cert in X5c.Values.Skip(1).Reverse())
                        {
                            chain.ChainPolicy.ExtraStore.Add(new X509Certificate2(cert.GetByteString()));
                        }
                    }
                    valid = chain.Build(new X509Certificate2(X5c.Values.First().GetByteString()));

                    if (_requireValidAttestationRoot)
                    {
                        // because we are using AllowUnknownCertificateAuthority we have to verify that the root matches ourselves
                        var chainRoot = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                        valid = valid && chainRoot.RawData.SequenceEqual(tpmRoots[i].RawData);
                    }

                    i++;
                }
                if (false == valid)
                    throw new Fido2VerificationException("TPM attestation failed chain validation");
                // The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
                // OID is 2.23.133.8.3
                var EKU = EKUFromAttnCertExts(aikCert.Extensions, "2.23.133.8.3");
                if (!EKU)
                    throw new Fido2VerificationException("aikCert EKU missing tcg-kp-AIKCertificate OID");

                // The Basic Constraints extension MUST have the CA component set to false.
                if (IsAttnCertCACert(aikCert.Extensions))
                    throw new Fido2VerificationException("aikCert Basic Constraints extension CA component must be false");

                // If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData
                var aaguid = AaguidFromAttnCertExts(aikCert.Extensions);
                if ((null != aaguid) &&
                    (!aaguid.SequenceEqual(Guid.Empty.ToByteArray())) &&
                    (0 != AttestedCredentialData.FromBigEndian(aaguid).CompareTo(AuthData.AttestedCredentialData.AaGuid)))
                    throw new Fido2VerificationException(string.Format("aaguid malformed, expected {0}, got {1}", AuthData.AttestedCredentialData.AaGuid, new Guid(aaguid)));
            }
            // If ecdaaKeyId is present, then the attestation type is ECDAA
            else if (null != EcdaaKeyId)
            {
                // Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo
                // https://www.w3.org/TR/webauthn/#biblio-fidoecdaaalgorithm
                throw new Fido2VerificationException("ECDAA support for TPM attestation is not yet implemented");
                // If successful, return attestation type ECDAA and the identifier of the ECDAA-Issuer public key ecdaaKeyId.
                //attnType = AttestationType.ECDAA;
                //trustPath = ecdaaKeyId;
            }
            else
            {
                throw new Fido2VerificationException("Neither x5c nor ECDAA were found in the TPM attestation statement");
            }
        }
        private static readonly Dictionary<int, TpmEccCurve> CoseCurveToTpm = new Dictionary<int, TpmEccCurve>
        {
            { 1, TpmEccCurve.TPM_ECC_NIST_P256},
            { 2, TpmEccCurve.TPM_ECC_NIST_P384},
            { 3, TpmEccCurve.TPM_ECC_NIST_P521}
        };
        private static string SANFromAttnCertExts(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.17")) // subject alternative name
                {
                    var asn = new AsnEncodedData(ext.Oid, ext.RawData);
                    return asn.Format(true);
                }
            }
            return null;
        }
        private static bool EKUFromAttnCertExts(X509ExtensionCollection exts, string expectedEnhancedKeyUsages)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.37") && ext is X509EnhancedKeyUsageExtension enhancedKeyUsageExtension)
                {
                    foreach (var oid in enhancedKeyUsageExtension.EnhancedKeyUsages)
                    {
                        if (expectedEnhancedKeyUsages.Equals(oid.Value))
                            return true;
                    }
                
                }
            }
            return false;
        }
    }

    public enum TpmEccCurve : ushort
    {
        // TCG TPM Rev 2.0, part 2, structures, section 6.4, TPM_ECC_CURVE
        TPM_ECC_NONE,       // 0x0000
        TPM_ECC_NIST_P192,  // 0x0001
        TPM_ECC_NIST_P224,  // 0x0002
        TPM_ECC_NIST_P256,  // 0x0003
        TPM_ECC_NIST_P384,  // 0x0004
        TPM_ECC_NIST_P521,  // 0x0005  
        TPM_ECC_BN_P256,    // 0x0010 curve to support ECDAA
        TPM_ECC_BN_P638,    // 0x0011 curve to support ECDAA
        TPM_ECC_SM2_P256    // 0x0020 
    }
    public enum TpmAlg : ushort
    {
        // TCG TPM Rev 2.0, part 2, structures, section 6.3, TPM_ALG_ID
        TPM_ALG_ERROR, // 0
        TPM_ALG_RSA, // 1
        TPM_ALG_SHA1 = 4, // 4
        TPM_ALG_HMAC, // 5
        TPM_ALG_AES, // 6
        TPM_ALG_MGF1, // 7
        TPM_ALG_KEYEDHASH, // 8
        TPM_ALG_XOR = 0xA, // A
        TPM_ALG_SHA256, // B
        TPM_ALG_SHA384, // C
        TPM_ALG_SHA512, // D
        TPM_ALG_NULL = 0x10, // 10
        TPM_ALG_SM3_256 = 0x12, // 12
        TPM_ALG_SM4, // 13
        TPM_ALG_RSASSA, // 14
        TPM_ALG_RSAES, // 15
        TPM_ALG_RSAPSS, // 16
        TPM_ALG_OAEP, // 17
        TPM_ALG_ECDSA, // 18
        TPM_ALG_ECDH, // 19
        TPM_ALG_ECDAA, // 1A
        TPM_ALG_SM2, // 1B
        TPM_ALG_ECSCHNORR, // 1C
        TPM_ALG_ECMQV, // 1D
        TPM_ALG_KDF1_SP800_56A = 0x20,
        TPM_ALG_KDF2, // 21
        TPM_ALG_KDF1_SP800_108, // 22
        TPM_ALG_ECC, // 23
        TPM_ALG_SYMCIPHER = 0x25,
        TPM_ALG_CAMELLIA, // 26
        TPM_ALG_CTR = 0x40,
        TPM_ALG_OFB, // 41
        TPM_ALG_CBC, // 42 
        TPM_ALG_CFB, // 43
        TPM_ALG_ECB // 44
    };
    // TPMS_ATTEST, TPMv2-Part2, section 10.12.8
    public class CertInfo
    {
        private static readonly Dictionary<TpmAlg, ushort> tpmAlgToDigestSizeMap = new Dictionary<TpmAlg, ushort>
        {
            {TpmAlg.TPM_ALG_SHA1,   (160/8) },
            {TpmAlg.TPM_ALG_SHA256, (256/8) },
            {TpmAlg.TPM_ALG_SHA384, (384/8) },
            {TpmAlg.TPM_ALG_SHA512, (512/8) }
        };
        public static (ushort size, byte[] name) NameFromTPM2BName(Memory<byte> ab, ref int offset)
        {
            // TCG TPM Rev 2.0, part 2, structures, section 10.5.3, TPM2B_NAME
            // This buffer holds a Name for any entity type. 
            // The type of Name in the structure is determined by context and the size parameter. 
            var totalBytes = AuthDataHelper.GetSizedByteArray(ab, ref offset, 2);
            ushort totalSize = 0;
            if (null != totalBytes)
            {
                totalSize = BitConverter.ToUInt16(totalBytes.ToArray().Reverse().ToArray(), 0);
            }
            ushort size = 0;
            var bytes = AuthDataHelper.GetSizedByteArray(ab, ref offset, 2);
            if (null != bytes)
            {
                size = BitConverter.ToUInt16(bytes.ToArray().Reverse().ToArray(), 0);
            }
            // If size is four, then the Name is a handle. 
            if (4 == size)
                throw new Fido2VerificationException("Unexpected handle in TPM2B_NAME");
            // If size is zero, then no Name is present. 
            if (0 == size)
                throw new Fido2VerificationException("Unexpected no name found in TPM2B_NAME");
            // Otherwise, the size shall be the size of a TPM_ALG_ID plus the size of the digest produced by the indicated hash algorithm.
            byte[] name = null;
            if (Enum.IsDefined(typeof(TpmAlg), size))
            {
                var tpmalg = (TpmAlg)size;
                if (tpmAlgToDigestSizeMap.ContainsKey(tpmalg))
                {
                    name = AuthDataHelper.GetSizedByteArray(ab, ref offset, tpmAlgToDigestSizeMap[tpmalg]);
                }
                else
                {
                    throw new Fido2VerificationException("TPM_ALG_ID found in TPM2B_NAME not acceptable hash algorithm");
                }
            }
            else
            {
                throw new Fido2VerificationException("Invalid TPM_ALG_ID found in TPM2B_NAME");
            }

            if (totalSize != bytes.Length + name.Length)
                throw new Fido2VerificationException("Unexpected extra bytes found in TPM2B_NAME");
            return (size, name);
        }

        public CertInfo(byte[] certInfo)
        {
            if (null == certInfo || 0 == certInfo.Length)
                throw new Fido2VerificationException("Malformed certInfo bytes");
            Raw = certInfo;
            var offset = 0;
            Magic = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 4);
            if (0xff544347 != BitConverter.ToUInt32(Magic.ToArray().Reverse().ToArray(), 0))
                throw new Fido2VerificationException("Bad magic number " + BitConverter.ToString(Magic).Replace("-",""));
            Type = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 2);
            if (0x8017 != BitConverter.ToUInt16(Type.ToArray().Reverse().ToArray(), 0))
                throw new Fido2VerificationException("Bad structure tag " + BitConverter.ToString(Type).Replace("-", ""));
            QualifiedSigner = AuthDataHelper.GetSizedByteArray(certInfo, ref offset);
            ExtraData = AuthDataHelper.GetSizedByteArray(certInfo, ref offset);
            if (null == ExtraData || 0 == ExtraData.Length)
                throw new Fido2VerificationException("Bad extraData in certInfo");
            Clock = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 8);
            ResetCount = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 4);
            RestartCount = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 4);
            Safe = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 1);
            FirmwareVersion = AuthDataHelper.GetSizedByteArray(certInfo, ref offset, 8);
            var (size, name) = NameFromTPM2BName(certInfo, ref offset);
            Alg = size; // TPM_ALG_ID
            AttestedName = name;
            AttestedQualifiedNameBuffer = AuthDataHelper.GetSizedByteArray(certInfo, ref offset);
            if (certInfo.Length != offset)
                throw new Fido2VerificationException("Leftover bits decoding certInfo");
        }
        public byte[] Raw { get; private set; }
        public byte[] Magic { get; private set; }
        public byte[] Type { get; private set; }
        public byte[] QualifiedSigner { get; private set; }
        public byte[] ExtraData { get; private set; }
        public byte[] Clock { get; private set; }
        public byte[] ResetCount { get; private set; }
        public byte[] RestartCount { get; private set; }
        public byte[] Safe { get; private set; }
        public byte[] FirmwareVersion { get; private set; }
        public ushort Alg { get; private set; }
        public byte[] AttestedName { get; private set; }
        public byte[] AttestedQualifiedNameBuffer { get; private set; }
    }
    // TPMT_PUBLIC, TPMv2-Part2, section 12.2.4
    public class PubArea
    {
        public PubArea(byte[] pubArea)
        {
            Raw = pubArea;
            var offset = 0;

            // TPMI_ALG_PUBLIC
            Type = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
            var tpmalg = (TpmAlg)Enum.Parse(typeof(TpmAlg), BitConverter.ToUInt16(Type.Reverse().ToArray(), 0).ToString());

            // TPMI_ALG_HASH 
            Alg = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);

            // TPMA_OBJECT, attributes that, along with type, determine the manipulations of this object 
            Attributes = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 4);

            // TPM2B_DIGEST, optional policy for using this key, computed using the alg of the object
            Policy = AuthDataHelper.GetSizedByteArray(pubArea, ref offset);

            // TPMU_PUBLIC_PARMS
            Symmetric = null;
            Scheme = null;

            if (TpmAlg.TPM_ALG_KEYEDHASH == tpmalg)
            {
                throw new Fido2VerificationException("TPM_ALG_KEYEDHASH not yet supported");
            }
            if (TpmAlg.TPM_ALG_SYMCIPHER == tpmalg)
            {
                throw new Fido2VerificationException("TPM_ALG_SYMCIPHER not yet supported");
            }

            // TPMS_ASYM_PARMS, for TPM_ALG_RSA and TPM_ALG_ECC
            if (TpmAlg.TPM_ALG_RSA == tpmalg || TpmAlg.TPM_ALG_ECC == tpmalg)
            {
                Symmetric = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
                Scheme = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
            }

            // TPMI_RSA_KEY_BITS, number of bits in the public modulus 
            KeyBits = null;
            // The public exponent, a prime number greater than 2. When zero, indicates that the exponent is the default of 2^16 + 1 
            Exponent = 0;

            if (TpmAlg.TPM_ALG_RSA == tpmalg)
            {
                KeyBits = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
                var tmp = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 4);
                if (null != tmp)
                {
                    Exponent = BitConverter.ToUInt32(tmp.ToArray(), 0);
                    if (0 == Exponent) Exponent = Convert.ToUInt32(Math.Pow(2, 16) + 1);
                }
            }

            // TPMI_ECC_CURVE
            CurveID = null;

            // TPMT_KDF_SCHEME, an optional key derivation scheme for generating a symmetric key from a Z value 
            // If the kdf  parameter associated with curveID is not TPM_ALG_NULL then this is required to be NULL. 
            // NOTE There are currently no commands where this parameter has effect and, in the reference code, this field needs to be set to TPM_ALG_NULL. 
            KDF = null;

            if (TpmAlg.TPM_ALG_ECC == tpmalg)
            {
                CurveID = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
                KDF = AuthDataHelper.GetSizedByteArray(pubArea, ref offset, 2);
            }

            // TPMU_PUBLIC_ID
            Unique = AuthDataHelper.GetSizedByteArray(pubArea, ref offset);
            if (pubArea.Length != offset)
                throw new Fido2VerificationException("Leftover bytes decoding pubArea");
        }
        public byte[] Raw { get; private set; }
        public byte[] Type { get; private set; }
        public byte[] Alg { get; private set; }
        public byte[] Attributes { get; private set; }
        public byte[] Policy { get; private set; }
        public byte[] Symmetric { get; private set; }
        public byte[] Scheme { get; private set; }
        public byte[] KeyBits { get; private set; }
        public uint Exponent { get; private set; }
        public byte[] CurveID { get; private set; }
        public byte[] KDF { get; private set; }
        public byte[] Unique { get; private set; }
        public TpmEccCurve EccCurve => (TpmEccCurve)Enum.Parse(typeof(TpmEccCurve), BitConverter.ToUInt16(CurveID.Reverse().ToArray(), 0).ToString());
        public ECPoint ECPoint
        {
            get
            {
                var point = new ECPoint();
                var uniqueOffset = 0;
                var size = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, 2);
                point.X = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, BitConverter.ToUInt16(size.Reverse().ToArray(), 0));
                size = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, 2);
                point.Y = AuthDataHelper.GetSizedByteArray(Unique, ref uniqueOffset, BitConverter.ToUInt16(size.Reverse().ToArray(), 0));
                return point;
            }
        }
    }
}
