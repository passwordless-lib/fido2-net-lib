﻿using PeterO.Cbor;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using Fido2NetLib.Objects;

namespace Fido2NetLib.AttestationFormat
{
    public abstract class AttestationFormat
    {
        public CBORObject attStmt;
        public byte[] authenticatorData;
        public byte[] clientDataHash;

        public AttestationFormat(CBORObject attStmt, byte[] authenticatorData, byte[] clientDataHash)
        {
            this.attStmt = attStmt;
            this.authenticatorData = authenticatorData;
            this.clientDataHash = clientDataHash;
        }

        internal CBORObject Sig => attStmt["sig"];
        internal CBORObject X5c => attStmt["x5c"];
        internal CBORObject Alg => attStmt["alg"];
        internal CBORObject EcdaaKeyId => attStmt["ecdaaKeyId"];
        internal AuthenticatorData AuthData => new AuthenticatorData(authenticatorData);
        internal CBORObject CredentialPublicKey => AuthData.AttestedCredentialData.CredentialPublicKey.GetCBORObject();
        internal byte[] Data
        {
            get
            {
                byte[] data = new byte[authenticatorData.Length + clientDataHash.Length];
                Buffer.BlockCopy(authenticatorData, 0, data, 0, authenticatorData.Length);
                Buffer.BlockCopy(clientDataHash, 0, data, authenticatorData.Length, clientDataHash.Length);
                return data;
            }
        }
        internal static byte[] AaguidFromAttnCertExts(X509ExtensionCollection exts)
        {
            byte[] aaguid = null;
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.1.1.4")) // id-fido-gen-ce-aaguid
                {
                    aaguid = new byte[16];
                    using (var ms = new System.IO.MemoryStream(ext.RawData.ToArray()))
                    {
                        // OCTET STRING
                        if (0x4 != ms.ReadByte())
                            throw new Fido2VerificationException("Expected octet string value");
                        // AAGUID
                        if (0x10 != ms.ReadByte())
                            throw new Fido2VerificationException("Unexpected length for aaguid");
                        ms.Read(aaguid, 0, 0x10);
                    }
                    //The extension MUST NOT be marked as critical
                    if (true == ext.Critical)
                        throw new Fido2VerificationException("extension MUST NOT be marked as critical");
                }
            }
            return aaguid;
        }
        internal static bool IsAttnCertCACert(X509ExtensionCollection exts)
        {
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("2.5.29.19") && ext is X509BasicConstraintsExtension baseExt)
                {
                    return baseExt.CertificateAuthority;
                }
            }
            return true;
        }
        internal static int U2FTransportsFromAttnCert(X509ExtensionCollection exts)
        {
            var u2ftransports = 0;
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.3.6.1.4.1.45724.2.1.1"))
                {
                    using (var ms = new System.IO.MemoryStream(ext.RawData.ToArray()))
                    {
                        if (0x3 != ms.ReadByte())
                            throw new Fido2VerificationException("Expected bit string");
                        if (0x2 != ms.ReadByte())
                            throw new Fido2VerificationException("Expected integer value");
                        var unusedBits = ms.ReadByte(); // number of unused bits
                        // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-authenticator-transports-extension-v1.2-ps-20170411.html
                        u2ftransports = ms.ReadByte(); // do something with this?
                    }
                }
            }
            return u2ftransports;
        }

        internal bool ValidateTrustChain(X509Certificate2[] trustPath, X509Certificate2[] attestationRootCertificates)
        {
            foreach (var attestationRootCert in attestationRootCertificates)
            {
                var chain = new X509Chain();
                chain.ChainPolicy.ExtraStore.Add(attestationRootCert);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                if (trustPath.Length > 1)
                {
                    foreach (var cert in trustPath.Skip(1).Reverse())
                    {
                        chain.ChainPolicy.ExtraStore.Add(cert);
                    }
                }
                var valid = chain.Build(trustPath[0]);

                // because we are using AllowUnknownCertificateAuthority we have to verify that the root matches ourselves
                var chainRoot = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                valid = valid && chainRoot.RawData.SequenceEqual(attestationRootCert.RawData);

                if (true == valid)
                    return true;
            }
            return false;
        }

        public abstract void Verify();
    }
}
