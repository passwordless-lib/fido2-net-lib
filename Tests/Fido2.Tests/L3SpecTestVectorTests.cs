using Fido2NetLib;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Runs the literal registration/assertion test vectors published in WebAuthn L3 <see href="https://www.w3.org/TR/webauthn-3/#sctn-test-vectors"/>
/// §16.4 ("crossOrigin": true) and §16.5 ("topOrigin" present) through the real verification pipeline, using the
/// spec's own byte-for-byte clientDataJSON/attestationObject/authenticatorData/signature values rather than
/// synthetically generated ones.
/// </summary>
public class L3SpecTestVectorTests
{
    private static byte[] Hex(string hex) => Convert.FromHexString(hex);

    private static CredentialCreateOptions BuildCreateOptions(byte[] challenge, string rp)
    {
        return new CredentialCreateOptions
        {
            Attestation = AttestationConveyancePreference.None,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                ResidentKey = ResidentKeyRequirement.Discouraged,
                UserVerification = UserVerificationRequirement.Discouraged,
            },
            Challenge = challenge,
            PubKeyCredParams = [PubKeyCredParam.ES256],
            Rp = new PublicKeyCredentialRpEntity(rp, rp, ""),
            User = new Fido2User
            {
                Name = "testuser",
                Id = "testuser"u8.ToArray(),
                DisplayName = "Test User",
            },
            Timeout = 60000,
        };
    }

    [Fact]
    public async Task Sctn_16_4_CrossOriginTrue_RegistrationAndAssertionAsync()
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256-crossOrigin
        var regChallenge = Hex("3be5aacd03537142472340ab5969f240f1d87716e20b6807ac230655fa4b3b49");
        var regClientDataJson = Hex("7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a224f2d57717a514e5463554a484930437257576e7951504859647862694332674872434d475666704c4f306b222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a207a5a7175457444523944577170573574425754467567227d");
        var regAttestationObject = Hex("a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54500000000883f4f6014f19c09d87aa38123be48d000206e1050c0d2ca2f07c755cb2c66a74c64fa43065c18f938354d9915db2bd5ce57a501020326200121582022200a473f90b11078851550d03b4e44a2279f8c4eca27b3153dedfe03e4e97d225820cbd0be95e746ad6f5a8191be11756e4c0420e72f65b466d39bc56b8b123a9c6e");
        var expectedAaGuid = new Guid(Hex("883f4f6014f19c09d87aa38123be48d0"), bigEndian: true);
        var expectedCredentialId = Hex("6e1050c0d2ca2f07c755cb2c66a74c64fa43065c18f938354d9915db2bd5ce57");

        var authChallenge = Hex("876aa517ba83fdee65fcffdbca4c84eeae5d54f8041a1fc85c991e5bbb273137");
        var authAuthenticatorData = Hex("bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50500000000");
        var authClientDataJson = Hex("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a226832716c463771445f65356c5f505f62796b7945377135645650674547685f49584a6b655737736e4d5463222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a2039327063545644304162792d713464746d6a36656667227d");
        var authSignature = Hex("3046022100eb12fcf23b12764c0f122e22371fab92e283879fd798f38ee1841c951b6e40e7022100c76237ff9db77b3c56f30837cda6a09acfa2e915544e609c0733b1184036d1cf");

        var lib = new Fido2(new Fido2Configuration
        {
            RPID = "example.org",
            RPName = "example.org",
            Origins = new HashSet<string> { "https://example.org" },
            AllowCrossOriginRequests = true,
        });

        var createOptions = BuildCreateOptions(regChallenge, "example.org");

        var rawAttestation = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "credId",
            RawId = expectedCredentialId,
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = regAttestationObject,
                ClientDataJson = regClientDataJson,
            },
        };

        var registered = await lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawAttestation,
            OriginalOptions = createOptions,
            IsCredentialIdUniqueToUserCallback = (_, _) => Task.FromResult(true),
        });

        Assert.Equal(expectedAaGuid, registered.AaGuid);
        Assert.Equal(expectedCredentialId, registered.Id);

        var assertionOptions = new AssertionOptions
        {
            Challenge = authChallenge,
            RpId = "example.org",
        };

        var rawAssertion = new AuthenticatorAssertionRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "credId",
            RawId = expectedCredentialId,
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = authAuthenticatorData,
                ClientDataJson = authClientDataJson,
                Signature = authSignature,
            },
        };

        var assertionResult = await lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = rawAssertion,
            OriginalOptions = assertionOptions,
            StoredPublicKey = registered.PublicKey,
            StoredSignatureCounter = registered.SignCount,
            IsUserHandleOwnerOfCredentialIdCallback = (_, _) => Task.FromResult(true),
        });

        Assert.Equal(expectedCredentialId, assertionResult.CredentialId);
    }

    [Fact]
    public async Task Sctn_16_5_TopOriginPresent_RegistrationAndAssertionAsync()
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256-topOrigin
        var regChallenge = Hex("4e1f4c6198699e33c14f192153f49d7e0e8e3577d5ac416c5f3adc92a41f27e5");
        var regClientDataJson = Hex("7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a225468394d595a68706e6a504254786b68555f53646667364f4e58665672454673587a72636b7151664a2d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22746f704f726967696e223a2268747470733a2f2f6578616d706c652e636f6d227d");
        var regAttestationObject = Hex("a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5410000000097586fd09799a76401c200455099ef2a0020b8ad59b996047ab18e2ceb57206c362da57458793481f4a8ebf101c7ca7cc0f1a5010203262001215820a1c47c1d82da4ebe82cd72207102b380670701993bc35398ae2e5726427fe01d22582086c1080d82987028c7f54ecb1b01185de243b359294a0ed210cd47480f0adc88");
        var expectedAaGuid = new Guid(Hex("97586fd09799a76401c200455099ef2a"), bigEndian: true);
        var expectedCredentialId = Hex("b8ad59b996047ab18e2ceb57206c362da57458793481f4a8ebf101c7ca7cc0f1");

        var authChallenge = Hex("d54a5c8ca4b62a8e3bb321e3b2bc73856f85a10150db2939ac195739eb1ea066");
        var authAuthenticatorData = Hex("bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50500000000");
        var authClientDataJson = Hex("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22315570636a4b53324b6f34377379486a7372787a68572d466f51465132796b3572426c584f6573656f4759222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22746f704f726967696e223a2268747470733a2f2f6578616d706c652e636f6d222c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205569466f4a4d56525148444146574669347678557051227d");
        var authSignature = Hex("3045022100b5a70c81780d5fcc9a4f2ae9caae99058f8accaf58b91fb59329646c28ac6ffc022012e101c165db3c8e9957f0c54dd6ca9b56bc3bd2f280bd2faa6c1d02c6e5c171");

        // The RP's own origin is https://example.org, but this ceremony additionally reports a
        // topOrigin of https://example.com (the page the RP expects to be sub-framed within, per
        // WebAuthn L3 §7.1/§7.2 and §13.4.9). Per this library's design, that's validated against
        // the same configured Origins allowlist as the primary origin check.
        var lib = new Fido2(new Fido2Configuration
        {
            RPID = "example.org",
            RPName = "example.org",
            Origins = new HashSet<string> { "https://example.org", "https://example.com" },
            AllowCrossOriginRequests = true,
        });

        var createOptions = BuildCreateOptions(regChallenge, "example.org");

        var rawAttestation = new AuthenticatorAttestationRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "credId",
            RawId = expectedCredentialId,
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = regAttestationObject,
                ClientDataJson = regClientDataJson,
            },
        };

        var registered = await lib.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = rawAttestation,
            OriginalOptions = createOptions,
            IsCredentialIdUniqueToUserCallback = (_, _) => Task.FromResult(true),
        });

        Assert.Equal(expectedAaGuid, registered.AaGuid);
        Assert.Equal(expectedCredentialId, registered.Id);

        var assertionOptions = new AssertionOptions
        {
            Challenge = authChallenge,
            RpId = "example.org",
        };

        var rawAssertion = new AuthenticatorAssertionRawResponse
        {
            Type = PublicKeyCredentialType.PublicKey,
            Id = "credId",
            RawId = expectedCredentialId,
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = authAuthenticatorData,
                ClientDataJson = authClientDataJson,
                Signature = authSignature,
            },
        };

        var assertionResult = await lib.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = rawAssertion,
            OriginalOptions = assertionOptions,
            StoredPublicKey = registered.PublicKey,
            StoredSignatureCounter = registered.SignCount,
            IsUserHandleOwnerOfCredentialIdCallback = (_, _) => Task.FromResult(true),
        });

        Assert.Equal(expectedCredentialId, assertionResult.CredentialId);
    }
}
