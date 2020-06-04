using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Fido2NetLib.AttestationFormat;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class StaticMetadataRepository : IMetadataRepository
    {
        protected readonly IDictionary<Guid, MetadataTOCPayloadEntry> _entries;
        protected MetadataTOCPayload _toc;
        protected readonly HttpClient _httpClient;
        protected readonly DateTime? _cacheUntil;

        // from https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt
        protected const string YUBICO_ROOT = "MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ" +
                                "dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw" +
                                "MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290" +
                                "IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK" +
                                "AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk" +
                                "5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep" +
                                "8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw" +
                                "nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT" +
                                "9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw" +
                                "LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ" +
                                "hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN" +
                                "BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4" +
                                "MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt" +
                                "hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k" +
                                "LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U" +
                                "sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc" +
                                "U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==";


        public StaticMetadataRepository(DateTime? cacheUntil = null)
        {
            _httpClient = new HttpClient();
            _entries = new Dictionary<Guid, MetadataTOCPayloadEntry>();
            _cacheUntil = cacheUntil;
        }

        public async Task<MetadataStatement> GetMetadataStatement(MetadataTOCPayloadEntry entry)
        {
            if (_toc == null)
                await GetToc();

            if (!string.IsNullOrEmpty(entry.AaGuid) && Guid.TryParse(entry.AaGuid, out Guid parsedAaGuid))
            {
                if (_entries.ContainsKey(parsedAaGuid))
                    return _entries[parsedAaGuid].MetadataStatement;
            }

            return null;
        }

        protected async Task<string> DownloadStringAsync(string url)
        {
            return await _httpClient.GetStringAsync(url);
        }


        public async Task<MetadataTOCPayload> GetToc()
        {
            var yubico = new MetadataTOCPayloadEntry
            {
                AaGuid = "f8a011f3-8c0a-4d15-8006-17111f9edc7d",
                Hash = "",
                StatusReports = new StatusReport[]
                {
                    new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED }
                },
                MetadataStatement = new MetadataStatement
                {
                    AttestationTypes = new ushort[]
                    {
                        (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL
                    },
                    Hash = "",
                    Description = "Yubico YubiKey FIDO2",
                    AttestationRootCertificates = new string[]
                    {
                        YUBICO_ROOT
                    }
                }
            };
            _entries.Add(new Guid(yubico.AaGuid), yubico);

            // YubiKey 5 USB and NFC AAGUID values from https://support.yubico.com/support/solutions/articles/15000014219-yubikey-5-series-technical-manual#AAGUID_Valuesxf002do
            var yubikey5usb = new MetadataTOCPayloadEntry
            {
                AaGuid = "cb69481e-8ff7-4039-93ec-0a2729a154a8",
                Hash = "",
                StatusReports = new StatusReport[]
                {
                    new StatusReport
                    {
                        Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED
                    }
                },
                MetadataStatement = new MetadataStatement
                {
                    AttestationTypes = new ushort[]
                    {
                        (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL
                    },
                    Hash = "",
                    Description = "Yubico YubiKey 5 USB",
                    AttestationRootCertificates = new string[]
                    {
                        YUBICO_ROOT
                    }
                }
            };
            _entries.Add(new Guid(yubikey5usb.AaGuid), yubikey5usb);

            var yubikey5nfc = new MetadataTOCPayloadEntry
            {
                AaGuid = "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
                Hash = "",
                StatusReports = new StatusReport[]
                {
                    new StatusReport
                    {
                        Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED
                    }
                },
                MetadataStatement = new MetadataStatement
                {
                    AttestationTypes = new ushort[]
                    {
                        (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL
                    },
                    Hash = "",
                    Description = "Yubico YubiKey 5 NFC",
                    AttestationRootCertificates = new string[]
                    {
                        YUBICO_ROOT
                    }
                }
            };
            _entries.Add(new Guid(yubikey5nfc.AaGuid), yubikey5nfc);

            var yubicoSecuriyKeyNfc = new MetadataTOCPayloadEntry
            {
                AaGuid = "6d44ba9b-f6ec-2e49-b930-0c8fe920cb73",
                Hash = "",
                StatusReports = new StatusReport[] { new StatusReport() { Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED } },
                MetadataStatement = new MetadataStatement
                {
                    Description = "Yubico Security Key NFC",
                    Icon = "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDIzLjAuMSwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPgo8c3ZnIHZlcnNpb249IjEuMSIgaWQ9Ill1YmljbyIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgeD0iMHB4IiB5PSIwcHgiCgkgdmlld0JveD0iMCAwIDc2OCA3NjgiIHN0eWxlPSJlbmFibGUtYmFja2dyb3VuZDpuZXcgMCAwIDc2OCA3Njg7IiB4bWw6c3BhY2U9InByZXNlcnZlIj4KPHN0eWxlIHR5cGU9InRleHQvY3NzIj4KCS5zdDB7ZmlsbDojOUFDQTNDO30KPC9zdHlsZT4KPHBvbHlnb24gaWQ9IlkiIGNsYXNzPSJzdDAiIHBvaW50cz0iMjE4LjQzLDIxMS44MSAzMTYuNDksMjExLjgxIDM4Ni41Miw0MDAuMDcgNDUzLjIsMjExLjgxIDU0OS41NywyMTEuODEgMzg3LjA4LDYxMS44NiAKCTI4Ni4yMyw2MTEuODYgMzMyLjE3LDUwMi4wNCAiLz4KPHBhdGggaWQ9IkNpcmNsZV8xXyIgY2xhc3M9InN0MCIgZD0iTTM4NCwwQzE3MS45MiwwLDAsMTcxLjkyLDAsMzg0czE3MS45MiwzODQsMzg0LDM4NHMzODQtMTcxLjkyLDM4NC0zODRTNTk2LjA4LDAsMzg0LDB6CgkgTTM4NCw2OTMuNThDMjEzLjAyLDY5My41OCw3NC40Miw1NTQuOTgsNzQuNDIsMzg0UzIxMy4wMiw3NC40MiwzODQsNzQuNDJTNjkzLjU4LDIxMy4wMiw2OTMuNTgsMzg0UzU1NC45OCw2OTMuNTgsMzg0LDY5My41OHoiLz4KPC9zdmc+Cg==",
                    AttachmentHint = 6,
                    AttestationTypes = new ushort[] { (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL },
                    Hash = "",
                    AttestationRootCertificates = new string[]
                    {
                        YUBICO_ROOT
                    }
                }
            };
            _entries.Add(new Guid(yubicoSecuriyKeyNfc.AaGuid), yubicoSecuriyKeyNfc);

            var msftWhfbSoftware = new MetadataTOCPayloadEntry
            {
                AaGuid = "6028B017-B1D4-4C02-B4B3-AFCDAFC96BB2",
                Hash = "",
                StatusReports = new StatusReport[]
                {
                    new StatusReport
                    {
                        Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED
                    }
                },
                MetadataStatement = new MetadataStatement
                {
                    AttestationTypes = new ushort[]
                    {
                        (ushort)MetadataAttestationType.ATTESTATION_BASIC_SURROGATE
                    },
                    Hash = "",
                    Description = "Windows Hello Software Authenticator",
                    AuthenticatorVersion = 1,
                    ProtocolFamily = "fido2",
                    Upv = new UafVersion[] 
                    { 
                        new UafVersion() 
                        { 
                            Major = 1,
                            Minor = 0 
                        } 
                    },
                    AssertionScheme = "FIDOV2",
                    AuthenticationAlgorithm = 12,
                    PublicKeyAlgAndEncoding = 260,
                    UserVerificationDetails = new VerificationMethodDescriptor[][]
                    {
                        new VerificationMethodDescriptor[]
                        {
                            new VerificationMethodDescriptor()
                            { 
                                UserVerification = 2 // USER_VERIFY_FINGERPRINT_INTERNAL
                            }
                        },
                        new VerificationMethodDescriptor[]
                        {
                            new VerificationMethodDescriptor()
                            {
                                UserVerification = 4 // USER_VERIFY_PASSCODE_INTERNAL
                            }
                        },
                        new VerificationMethodDescriptor[]
                        {
                            new VerificationMethodDescriptor()
                            {
                                UserVerification = 16 // USER_VERIFY_FACEPRINT_INTERNAL
                            }
                        },
                        new VerificationMethodDescriptor[]
                        {
                             new VerificationMethodDescriptor()
                            {
                                UserVerification = 64 // USER_VERIFY_EYEPRINT_INTERNAL
                            }
                        }
                    },
                    KeyProtection = 2, // KEY_PROTECTION_HARDWARE
                    MatcherProtection = 1, // MATCHER_PROTECTION_SOFTWARE
                    AttachmentHint = 1, // ATTACHMENT_HINT_INTERNAL
                    IsSecondFactorOnly = false,
                    TcDisplay = 0,
                    Icon = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEgAAABICAYAAABV7bNHAAACkUlEQVR42uyai3GDMAyGQyegGzACnaCMkBHoBhkhnSAj0A2SDaAT0E6QbEA3cOXW6XEpBtnImMv9utOllxjF/qKHLTdRSm0gdnkAAgACIAACIAACIAACIAgAARAAARAAARAAARBEAFCSJINKkpLuSTtSZbQz76W25zhKkpFWPbtaz6Q75vPuoluuPmqxlZK2yi76s9RznjlpN2K7CrFWaUAHNS0HT0Atw3YpDSjxbdoPuaziG3uk579cvIdeWsbQD7L7NAYoWpKmLy8chueO5reB7KKKrQnQJdDYn9AJZHc5QBT7enINY2hjxrqItsvJWSdxFxKuYlOlWJmE6zPPcsJuN7WFiF7me5DOAws4OyZyG6TOsr/KQziDaJm/mcy2V1V0+T0JeXxqqlrWC9mGGy3O6wwFaI0SdR+EMg9AEAACIAByqViZb+/prgFdN6qb306j3lTWs0BJ76Qjw0ktO+3ad60PQhMrfM9YwqK7lUPe4j+/OR40cDaqJeJ+xo80JsWih1WTBAcb8ysKrb+TfowQKy3v55wbBkk49FJbQusqr4snadL9hEtXC3nO1G1HG6UfxIj5oDnJlHPOVVAerWGmvYQxwc70hiTh7Bidy3/3ZFE6isxf8epNhUCl4n5ftYqWKzMP3IIquaFnquXO0sZ1yn/RWq69SuK6GdPXORfSz4HPnk1bNXO0+UZze5HqKIodNYwnHVVcOUivNcStxj4CGFYhWAWgXgmuF4JzdMhn6wDUm1DpmFyVY7IvQqeTRdod2v2F8lNn/gcpW+rUsOi9mAmFwlSo3Pw9JQ3p+8bhgnAMkPM613BxOBQqc2FEB4SmPQSAAAiAAAiAAAiAAAiAIAAEQAAEQAAEQPco3wIMADOXgFhOTghuAAAAAElFTkSuQmCC"
                }
            };
            _entries.Add(new Guid(msftWhfbSoftware.AaGuid), msftWhfbSoftware);
            var msftWhfbSoftwareVbs = new MetadataTOCPayloadEntry
            {
                AaGuid = "6E96969E-A5CF-4AAD-9B56-305FE6C82795",
                Hash = "",
                StatusReports = new StatusReport[]
                {
                    new StatusReport
                    {
                        Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED
                    }
                },
                MetadataStatement = new MetadataStatement
                {
                    AttestationTypes = new ushort[]
                    {
                        (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL
                    },
                    Hash = "",
                    Description = "Windows Hello VBS software authenticator"
                }
            };
            _entries.Add(new Guid(msftWhfbSoftwareVbs.AaGuid), msftWhfbSoftwareVbs);
            var msftWhfbHardware = new MetadataTOCPayloadEntry
            {
                AaGuid = "08987058-CADC-4B81-B6E1-30DE50DCBE96",
                Hash = "",
                StatusReports = new StatusReport[]
                {
                    new StatusReport
                    {
                        Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED
                    }
                },
                MetadataStatement = new MetadataStatement
                {
                    AttestationTypes = new ushort[]
                    {
                        15888
                    },
                    Hash = "",
                    Description = "Windows Hello Hardware Authenticator",
                    AttestationRootCertificates = new string[]
                    {
                        "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",
                    },
                    AuthenticatorVersion = 1,
                    ProtocolFamily = "fido2",
                    Upv = new UafVersion[]
                    {
                        new UafVersion()
                        {
                            Major = 1,
                            Minor = 0
                        }
                    },
                    AssertionScheme = "FIDOV2",
                    AuthenticationAlgorithm = 12,
                    PublicKeyAlgAndEncoding = 260,
                    UserVerificationDetails = new VerificationMethodDescriptor[][]
                    {
                        new VerificationMethodDescriptor[]
                        {
                            new VerificationMethodDescriptor()
                            {
                                UserVerification = 2 // USER_VERIFY_FINGERPRINT_INTERNAL
                            }
                        },
                        new VerificationMethodDescriptor[]
                        {
                            new VerificationMethodDescriptor()
                            {
                                UserVerification = 4 // USER_VERIFY_PASSCODE_INTERNAL
                            }
                        },
                        new VerificationMethodDescriptor[]
                        {
                            new VerificationMethodDescriptor()
                            {
                                UserVerification = 16 // USER_VERIFY_FACEPRINT_INTERNAL
                            }
                        },
                        new VerificationMethodDescriptor[]
                        {
                             new VerificationMethodDescriptor()
                            {
                                UserVerification = 64 // USER_VERIFY_EYEPRINT_INTERNAL
                            }
                        }
                    },
                    KeyProtection = 2, // KEY_PROTECTION_HARDWARE
                    MatcherProtection = 1, // MATCHER_PROTECTION_SOFTWARE
                    AttachmentHint = 1, // ATTACHMENT_HINT_INTERNAL
                    IsSecondFactorOnly = false,
                    TcDisplay = 0,
                    Icon = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEgAAABICAYAAABV7bNHAAACkUlEQVR42uyai3GDMAyGQyegGzACnaCMkBHoBhkhnSAj0A2SDaAT0E6QbEA3cOXW6XEpBtnImMv9utOllxjF/qKHLTdRSm0gdnkAAgACIAACIAACIAACIAgAARAAARAAARAAARBEAFCSJINKkpLuSTtSZbQz76W25zhKkpFWPbtaz6Q75vPuoluuPmqxlZK2yi76s9RznjlpN2K7CrFWaUAHNS0HT0Atw3YpDSjxbdoPuaziG3uk579cvIdeWsbQD7L7NAYoWpKmLy8chueO5reB7KKKrQnQJdDYn9AJZHc5QBT7enINY2hjxrqItsvJWSdxFxKuYlOlWJmE6zPPcsJuN7WFiF7me5DOAws4OyZyG6TOsr/KQziDaJm/mcy2V1V0+T0JeXxqqlrWC9mGGy3O6wwFaI0SdR+EMg9AEAACIAByqViZb+/prgFdN6qb306j3lTWs0BJ76Qjw0ktO+3ad60PQhMrfM9YwqK7lUPe4j+/OR40cDaqJeJ+xo80JsWih1WTBAcb8ysKrb+TfowQKy3v55wbBkk49FJbQusqr4snadL9hEtXC3nO1G1HG6UfxIj5oDnJlHPOVVAerWGmvYQxwc70hiTh7Bidy3/3ZFE6isxf8epNhUCl4n5ftYqWKzMP3IIquaFnquXO0sZ1yn/RWq69SuK6GdPXORfSz4HPnk1bNXO0+UZze5HqKIodNYwnHVVcOUivNcStxj4CGFYhWAWgXgmuF4JzdMhn6wDUm1DpmFyVY7IvQqeTRdod2v2F8lNn/gcpW+rUsOi9mAmFwlSo3Pw9JQ3p+8bhgnAMkPM613BxOBQqc2FEB4SmPQSAAAiAAAiAAAiAAAiAIAAEQAAEQAAEQPco3wIMADOXgFhOTghuAAAAAElFTkSuQmCC"
                }
            };
            _entries.Add(new Guid(msftWhfbHardware.AaGuid), msftWhfbHardware);
            var msftWhfbHardwareVbs = new MetadataTOCPayloadEntry
            {
                AaGuid = "9DDD1817-AF5A-4672-A2B9-3E3DD95000A9",
                Hash = "",
                StatusReports = new StatusReport[]
                {
                    new StatusReport
                    {
                        Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED
                    }
                },
                MetadataStatement = new MetadataStatement
                {
                    AttestationTypes = new ushort[]
                    {
                        (ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL
                    },
                    Hash = "",
                    Description = "Windows Hello VBS Hardware Authenticator",
                    AttestationRootCertificates = new string[]
                    {
                        "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",
                    },
                    AuthenticatorVersion = 1,
                    ProtocolFamily = "fido2",
                    Upv = new UafVersion[]
                    {
                        new UafVersion()
                        {
                            Major = 1,
                            Minor = 0
                        }
                    },
                    AssertionScheme = "FIDOV2",
                    AuthenticationAlgorithm = 12,
                    PublicKeyAlgAndEncoding = 260,
                    UserVerificationDetails = new VerificationMethodDescriptor[][]
                    {
                        new VerificationMethodDescriptor[]
                        {
                            new VerificationMethodDescriptor()
                            {
                                UserVerification = 2 // USER_VERIFY_FINGERPRINT_INTERNAL
                            }
                        },
                        new VerificationMethodDescriptor[]
                        {
                            new VerificationMethodDescriptor()
                            {
                                UserVerification = 4 // USER_VERIFY_PASSCODE_INTERNAL
                            }
                        },
                        new VerificationMethodDescriptor[]
                        {
                            new VerificationMethodDescriptor()
                            {
                                UserVerification = 16 // USER_VERIFY_FACEPRINT_INTERNAL
                            }
                        },
                        new VerificationMethodDescriptor[]
                        {
                             new VerificationMethodDescriptor()
                            {
                                UserVerification = 64 // USER_VERIFY_EYEPRINT_INTERNAL
                            }
                        }
                    },
                    KeyProtection = 6, // KEY_PROTECTION_HARDWARE & KEY_PROTECTION_TEE
                    MatcherProtection = 2, // MATCHER_PROTECTION_TEE
                    AttachmentHint = 1, // ATTACHMENT_HINT_INTERNAL
                    IsSecondFactorOnly = false,
                    TcDisplay = 0,
                    Icon = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEgAAABICAYAAABV7bNHAAACkUlEQVR42uyai3GDMAyGQyegGzACnaCMkBHoBhkhnSAj0A2SDaAT0E6QbEA3cOXW6XEpBtnImMv9utOllxjF/qKHLTdRSm0gdnkAAgACIAACIAACIAACIAgAARAAARAAARAAARBEAFCSJINKkpLuSTtSZbQz76W25zhKkpFWPbtaz6Q75vPuoluuPmqxlZK2yi76s9RznjlpN2K7CrFWaUAHNS0HT0Atw3YpDSjxbdoPuaziG3uk579cvIdeWsbQD7L7NAYoWpKmLy8chueO5reB7KKKrQnQJdDYn9AJZHc5QBT7enINY2hjxrqItsvJWSdxFxKuYlOlWJmE6zPPcsJuN7WFiF7me5DOAws4OyZyG6TOsr/KQziDaJm/mcy2V1V0+T0JeXxqqlrWC9mGGy3O6wwFaI0SdR+EMg9AEAACIAByqViZb+/prgFdN6qb306j3lTWs0BJ76Qjw0ktO+3ad60PQhMrfM9YwqK7lUPe4j+/OR40cDaqJeJ+xo80JsWih1WTBAcb8ysKrb+TfowQKy3v55wbBkk49FJbQusqr4snadL9hEtXC3nO1G1HG6UfxIj5oDnJlHPOVVAerWGmvYQxwc70hiTh7Bidy3/3ZFE6isxf8epNhUCl4n5ftYqWKzMP3IIquaFnquXO0sZ1yn/RWq69SuK6GdPXORfSz4HPnk1bNXO0+UZze5HqKIodNYwnHVVcOUivNcStxj4CGFYhWAWgXgmuF4JzdMhn6wDUm1DpmFyVY7IvQqeTRdod2v2F8lNn/gcpW+rUsOi9mAmFwlSo3Pw9JQ3p+8bhgnAMkPM613BxOBQqc2FEB4SmPQSAAAiAAAiAAAiAAAiAIAAEQAAEQAAEQPco3wIMADOXgFhOTghuAAAAAElFTkSuQmCC"
                }
            };
            _entries.Add(new Guid(msftWhfbHardwareVbs.AaGuid), msftWhfbHardwareVbs);

            var solostatement = await DownloadStringAsync("https://raw.githubusercontent.com/solokeys/solo/master/metadata/Solo-FIDO2-CTAP2-Authenticator.json");
            var soloMetadataStatement = JsonConvert.DeserializeObject<MetadataStatement>(solostatement);
            var soloKeysSolo = new MetadataTOCPayloadEntry
            {
                AaGuid = soloMetadataStatement.AaGuid,
                Url = "https://raw.githubusercontent.com/solokeys/solo/master/metadata/Solo-FIDO2-CTAP2-Authenticator.json",
                StatusReports = new StatusReport[]
                {
                    new StatusReport
                    {
                        Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED
                    }
                },
                MetadataStatement = soloMetadataStatement
            };
            _entries.Add(new Guid(soloKeysSolo.AaGuid), soloKeysSolo);

            var soloTapStatement = await DownloadStringAsync("https://raw.githubusercontent.com/solokeys/solo/master/metadata/SoloTap-FIDO2-CTAP2-Authenticator.json");
            var soloTapMetadataStatement = JsonConvert.DeserializeObject<MetadataStatement>(soloTapStatement);
            var soloTapMetadata = new MetadataTOCPayloadEntry
            {
                AaGuid = soloTapMetadataStatement.AaGuid,
                Url = "https://raw.githubusercontent.com/solokeys/solo/master/metadata/SoloTap-FIDO2-CTAP2-Authenticator.json",
                StatusReports = new StatusReport[]
                {
                    new StatusReport
                    {
                        Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED
                    }
                },
                MetadataStatement = soloTapMetadataStatement
            };
            _entries.Add(new Guid(soloTapMetadata.AaGuid), soloTapMetadata);

            var soloSomuStatement = await DownloadStringAsync("https://raw.githubusercontent.com/solokeys/solo/master/metadata/Somu-FIDO2-CTAP2-Authenticator.json");
            var soloSomuMetadataStatement = JsonConvert.DeserializeObject<MetadataStatement>(soloSomuStatement);
            var soloSomuMetadata = new MetadataTOCPayloadEntry
            {
                AaGuid = soloSomuMetadataStatement.AaGuid,
                Url = "https://raw.githubusercontent.com/solokeys/solo/master/metadata/Somu-FIDO2-CTAP2-Authenticator.json",
                StatusReports = new StatusReport[]
                {
                    new StatusReport
                    {
                        Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED
                    }
                },
                MetadataStatement = soloSomuMetadataStatement
            };
            _entries.Add(new Guid(soloSomuMetadata.AaGuid), soloSomuMetadata);

            foreach (var entry in _entries)
            {
                entry.Value.MetadataStatement.AaGuid = entry.Value.AaGuid;
            }

            _toc = new MetadataTOCPayload()
            {
                Entries = _entries.Select(o => o.Value).ToArray(),
                NextUpdate = _cacheUntil?.ToString("yyyy-MM-dd") ?? "", //Results in no caching
                LegalHeader = "Static FAKE",
                Number = 1
            };

            return _toc;
        }
    }
}
