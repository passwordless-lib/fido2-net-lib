#nullable disable

using System;
using System.Buffers.Binary;
using System.IO;
using System.Runtime.InteropServices;

namespace Fido2NetLib.Objects
{
    public sealed class AttestedCredentialData
    {
        /// <summary>
        /// Minimum length of the attested credential data structure.  AAGUID + credentialID length + credential ID + credential public key.
        /// <see cref="https://www.w3.org/TR/webauthn/#attested-credential-data"/>
        /// </summary>
        private readonly int _minLength = Marshal.SizeOf(typeof(Guid)) + sizeof(ushort) + sizeof(byte) + sizeof(byte);

        /// <summary>
        /// The AAGUID of the authenticator. Can be used to identify the make and model of the authenticator.
        /// <see cref="https://www.w3.org/TR/webauthn/#aaguid"/>
        /// </summary>
        public Guid AaGuid { get; private set; }

        /// <summary>
        /// A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
        /// <see cref="https://www.w3.org/TR/webauthn/#credential-id"/>
        /// </summary>
        public byte[] CredentialID { get; private set; }

        /// <summary>
        /// The credential public key encoded in COSE_Key format, as defined in 
        /// Section 7 of RFC8152, using the CTAP2 canonical CBOR encoding form.
        /// <see cref="https://www.w3.org/TR/webauthn/#credential-public-key"/>
        /// </summary>
        public CredentialPublicKey CredentialPublicKey { get; private set; }

        internal static void SwapBytes(byte[] bytes, int index1, int index2)
        {
            var temp = bytes[index1];
            bytes[index1] = bytes[index2];
            bytes[index2] = temp;
        }

        /// <summary>
        /// AAGUID is sent as big endian byte array, this converter is for little endian systems.
        /// </summary>
        public static Guid FromBigEndian(byte[] Aaguid)
        {
            SwapBytes(Aaguid, 0, 3);
            SwapBytes(Aaguid, 1, 2);
            SwapBytes(Aaguid, 4, 5);
            SwapBytes(Aaguid, 6, 7);

            return new Guid(Aaguid);
        }

        /// <summary>
        /// AAGUID is sent as big endian byte array, this converter is for little endian systems.
        /// </summary>
        public static byte[] AaGuidToBigEndian(Guid AaGuid)
        {
            var aaguid = AaGuid.ToByteArray();

            SwapBytes(aaguid, 0, 3);
            SwapBytes(aaguid, 1, 2);
            SwapBytes(aaguid, 4, 5);
            SwapBytes(aaguid, 6, 7);

            return aaguid;
        }

        /// <summary>
        /// Instantiates an AttestedCredentialData object from an aaguid, credentialID, and CredentialPublicKey
        /// </summary>
        /// <param name="aaguid"></param>
        /// <param name="credentialID"></param>
        /// <param name="cpk"></param>
        public AttestedCredentialData(Guid aaguid, byte[] credentialID, CredentialPublicKey cpk)
        {
            AaGuid = aaguid;
            CredentialID = credentialID;
            CredentialPublicKey = cpk;
        }

        public AttestedCredentialData(byte[] bytes) : this(new BinaryReader(new MemoryStream(bytes, false)))
        {
        }

        /// <summary>
        /// Decodes attested credential data.
        /// </summary>
        public AttestedCredentialData(BinaryReader reader)
        {
            if (reader.BaseStream.Length < _minLength)
                throw new Fido2VerificationException("Not enough bytes to be a valid AttestedCredentialData");
            // First 16 bytes is AAGUID
            var aaguidBytes = reader.ReadBytes(Marshal.SizeOf(typeof(Guid)));

            if (BitConverter.IsLittleEndian)
            {
                // GUID from authenticator is big endian. If we are on a little endian system, convert.
                AaGuid = FromBigEndian(aaguidBytes);
            }
            else
            {
                AaGuid = new Guid(aaguidBytes);
            }

            // Byte length of Credential ID, 16-bit unsigned big-endian integer. 
            var credentialIDLen = BinaryPrimitives.ReadUInt16BigEndian(reader.ReadBytes(sizeof(ushort)));

            // Read the credential ID bytes
            CredentialID = reader.ReadBytes(credentialIDLen);

            // "Determining attested credential data's length, which is variable, involves determining 
            // credentialPublicKey's beginning location given the preceding credentialId's length, and 
            // then determining the credentialPublicKey's length"

            // Read the CBOR object from the stream
            CredentialPublicKey = new CredentialPublicKey(reader.BaseStream);
        }

        public override string ToString()
        {
            return $"AAGUID: {AaGuid}, CredentialID: {CredentialID.ToString().Replace("-", "")}, CredentialPublicKey: {CredentialPublicKey}";
        }

        public byte[] ToByteArray()
        {
            using (var ms = new MemoryStream())
            {
                using (var writer = new BinaryWriter(ms))
                {
                    // Write the aaguid bytes out, reverse if we're on a little endian system
                    if (BitConverter.IsLittleEndian)
                    {
                        writer.Write(AaGuidToBigEndian(AaGuid));
                    }
                    else
                    {
                        writer.Write(AaGuid.ToByteArray());
                    }

                    // Write the length of credential ID, as big endian bytes of a 16-bit unsigned integer
                    writer.WriteUInt16BigEndian((ushort)CredentialID.Length);
                    
                    // Write CredentialID bytes
                    writer.Write(CredentialID);

                    // Write credential public key bytes
                    writer.Write(CredentialPublicKey.GetBytes());
                }
                return ms.ToArray();
            }
        }
    }
}
