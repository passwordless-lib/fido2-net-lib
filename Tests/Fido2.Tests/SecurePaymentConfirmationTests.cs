#nullable enable

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using fido2_net_lib.Test;

using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace Test;

/// <summary>
/// Secure Payment Confirmation: an assertion whose client data is of type "payment.get" and carries the transaction
/// the user confirmed (https://www.w3.org/TR/secure-payment-confirmation/#sctn-verifying-assertion).
/// </summary>
public class SecurePaymentConfirmationTests
{
    private const string RpId = "bank.example";
    private const string RpOrigin = "https://bank.example";
    private const string MerchantOrigin = "https://merchant.example";

    private static readonly byte[] s_credentialId = [0xf1, 0xd0, 0xf1, 0xd0];

    private static SecurePaymentConfirmationExpectations Expectations() => new()
    {
        TopOrigin = MerchantOrigin,
        PayeeOrigin = MerchantOrigin,
        Total = new PaymentCurrencyAmount { Currency = "USD", Value = "10.00" },
        Instrument = new PaymentCredentialInstrument { DisplayName = "Visa ****1234", Icon = "https://bank.example/card.png" },
        PaymentEntitiesLogos = [Logo("a"), Logo("b"), Logo("c")],
    };

    private static PaymentEntityLogo Logo(string name) => new() { Url = $"https://logos.example/{name}.png", Label = name };

    /// <summary>
    /// The "payment" member as Chrome would sign it for <see cref="Expectations"/>, with any member overridden.
    /// </summary>
    private static Dictionary<string, object?> Payment(
        string? rpId = RpId,
        string? topOrigin = MerchantOrigin,
        string? payeeName = null,
        string? payeeOrigin = MerchantOrigin,
        object? logos = null,
        object? total = null,
        object? instrument = null,
        string? browserBoundPublicKey = null,
        string? rp = null,
        bool omitTotal = false,
        bool omitInstrument = false)
    {
        var payment = new Dictionary<string, object?>
        {
            ["rpId"] = rpId,
            ["topOrigin"] = topOrigin,
        };

        if (!omitTotal)
            payment["total"] = total ?? new { currency = "USD", value = "10.00" };
        if (!omitInstrument)
            payment["instrument"] = instrument ?? new { displayName = "Visa ****1234", icon = "https://bank.example/card.png" };

        if (payeeName is not null)
            payment["payeeName"] = payeeName;
        if (payeeOrigin is not null)
            payment["payeeOrigin"] = payeeOrigin;
        if (logos is not null)
            payment["paymentEntitiesLogos"] = logos;
        if (browserBoundPublicKey is not null)
            payment["browserBoundPublicKey"] = browserBoundPublicKey;
        if (rp is not null)
            payment["rp"] = rp;

        return payment;
    }

    private sealed class Ceremony
    {
        public ECDsa CredentialKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public byte[] Challenge { get; } = RandomNumberGenerator.GetBytes(32);
        public CredentialPublicKey PublicKey { get; }

        public Ceremony()
        {
            var q = CredentialKey.ExportParameters(false).Q;
            PublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, q.X, q.Y);
        }

        public byte[] ClientDataJson(string type, string origin, Dictionary<string, object?>? payment)
        {
            var clientData = new Dictionary<string, object?>
            {
                ["type"] = type,
                ["challenge"] = Base64Url.EncodeToString(Challenge),
                ["origin"] = origin,
            };

            if (payment is not null)
                clientData["payment"] = payment;

            return JsonSerializer.SerializeToUtf8Bytes(clientData);
        }

        public AuthenticatorAssertionRawResponse Assert(byte[] clientDataJson, AuthenticationExtensionsClientOutputs? extensionResults = null)
        {
            var authenticatorData = new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(RpId)), AuthenticatorFlags.UP | AuthenticatorFlags.UV, 1, null, null).ToByteArray();
            byte[] toBeSigned = [.. authenticatorData, .. SHA256.HashData(clientDataJson)];

            return new AuthenticatorAssertionRawResponse
            {
                Id = Base64Url.EncodeToString(s_credentialId),
                RawId = s_credentialId,
                Type = PublicKeyCredentialType.PublicKey,
                ClientExtensionResults = extensionResults ?? new AuthenticationExtensionsClientOutputs(),
                Response = new AuthenticatorAssertionRawResponse.AssertionResponse
                {
                    AuthenticatorData = authenticatorData,
                    ClientDataJson = clientDataJson,
                    Signature = CredentialKey.SignData(toBeSigned, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence),
                },
            };
        }

        public Task<VerifyAssertionResult> VerifyAsync(AuthenticatorAssertionRawResponse response, SecurePaymentConfirmationExpectations? expectations, params string[] origins)
        {
            var fido2 = new Fido2(new Fido2Configuration { RPID = RpId, RPName = "Bank", Origins = new HashSet<string>(origins.Length == 0 ? [RpOrigin] : origins) });

            return fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = response,
                OriginalOptions = new AssertionOptions { Challenge = Challenge, RpId = RpId, AllowCredentials = [new PublicKeyCredentialDescriptor(s_credentialId)] },
                StoredPublicKey = PublicKey.GetBytes(),
                StoredSignatureCounter = 0,
                IsUserHandleOwnerOfCredentialIdCallback = (_, _) => Task.FromResult(true),
                SecurePaymentConfirmation = expectations,
            });
        }
    }

    [Fact]
    public async Task Payment_assertion_verifies_when_it_matches_the_transaction()
    {
        var ceremony = new Ceremony();

        // The RP's iframe on the merchant page called SPC, so the origin is the RP's own and the merchant is the top origin
        var response = ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, Payment(logos: new[] { new { url = Logo("a").Url, label = "a" }, new { url = Logo("c").Url, label = "c" } })));

        var result = await ceremony.VerifyAsync(response, Expectations());

        Assert.Equal(s_credentialId, result.CredentialId);
        Assert.Null(result.BrowserBoundPublicKey);
    }

    [Fact]
    public async Task Payment_assertion_is_refused_as_a_login()
    {
        // SPC §11.1.1: a payment assertion posted to the login endpoint must not log the user in
        var ceremony = new Ceremony();
        var response = ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, Payment()));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(response, expectations: null));

        Assert.Equal(Fido2ErrorCode.InvalidAssertionResponse, ex.Code);
        Assert.Contains("webauthn.get", ex.Message);
    }

    [Fact]
    public async Task Login_assertion_is_refused_as_a_payment()
    {
        var ceremony = new Ceremony();
        var response = ceremony.Assert(ceremony.ClientDataJson("webauthn.get", RpOrigin, payment: null));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(response, Expectations()));

        Assert.Equal(Fido2ErrorCode.InvalidAssertionResponse, ex.Code);
        Assert.Contains("payment.get", ex.Message);
    }

    [Fact]
    public async Task Merchant_may_call_SPC_directly_when_the_expectations_allow_its_origin()
    {
        var ceremony = new Ceremony();
        var response = ceremony.Assert(ceremony.ClientDataJson("payment.get", MerchantOrigin, Payment()));

        // The configured origins are the RP's own; a login from the merchant's origin would be refused
        await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(response, Expectations()));

        // For this payment, the RP expects the merchant to have called SPC
        var expectations = new SecurePaymentConfirmationExpectations
        {
            TopOrigin = MerchantOrigin,
            PayeeOrigin = MerchantOrigin,
            Total = Expectations().Total,
            Instrument = Expectations().Instrument,
            PaymentEntitiesLogos = Expectations().PaymentEntitiesLogos,
            Origins = new HashSet<string> { MerchantOrigin },
        };

        await ceremony.VerifyAsync(response, expectations);
    }

    public static IEnumerable<object[]> Mismatches()
    {
        yield return ["rpId is another RP", Payment(rpId: "other.example")];
        yield return ["rpId is missing", Payment(rpId: null)];
        yield return ["rp and rpId disagree", Payment(rp: "other.example")];
        yield return ["topOrigin is another site", Payment(topOrigin: "https://evil.example")];
        yield return ["topOrigin is missing", Payment(topOrigin: null)];
        yield return ["payeeName was shown but none was expected", Payment(payeeName: "Merchant Inc")];
        yield return ["payeeOrigin differs", Payment(payeeOrigin: "https://evil.example")];
        yield return ["payeeOrigin was expected but not shown", Payment(payeeOrigin: null)];
        yield return ["total value differs", Payment(total: new { currency = "USD", value = "100.00" })];
        yield return ["total currency differs", Payment(total: new { currency = "EUR", value = "10.00" })];
        yield return ["total is missing", Payment(omitTotal: true)];
        yield return ["instrument is missing", Payment(omitInstrument: true)];
        yield return ["instrument name differs", Payment(instrument: new { displayName = "Visa ****9999", icon = "https://bank.example/card.png" })];
        yield return ["instrument icon differs", Payment(instrument: new { displayName = "Visa ****1234", icon = "https://evil.example/card.png" })];
        yield return ["instrument icon was not required to be shown", Payment(instrument: new { displayName = "Visa ****1234", icon = "https://bank.example/card.png", iconMustBeShown = false })];
        yield return ["instrument has details that were not offered", Payment(instrument: new { displayName = "Visa ****1234", icon = "https://bank.example/card.png", details = "Platinum" })];
        yield return ["a logo that was not offered", Payment(logos: new[] { new { url = "https://evil.example/logo.png", label = "a" } })];
        yield return ["offered logos out of order", Payment(logos: new[] { new { url = Logo("c").Url, label = "c" }, new { url = Logo("a").Url, label = "a" } })];
        yield return ["a logo with another label", Payment(logos: new[] { new { url = Logo("a").Url, label = "not a" } })];
    }

    [Theory]
    [MemberData(nameof(Mismatches))]
    public async Task Payment_assertion_is_refused_when_what_was_signed_differs_from_what_was_expected(string because, Dictionary<string, object?> payment)
    {
        var ceremony = new Ceremony();
        var response = ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, payment));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(response, Expectations()));

        Assert.True(ex.Code == Fido2ErrorCode.InvalidPaymentData, $"{because}: {ex.Message}");
        Assert.StartsWith("Secure Payment Confirmation data does not match the transaction", ex.Message);
    }

    [Fact]
    public async Task Payment_member_missing_a_required_field_is_malformed_client_data()
    {
        var ceremony = new Ceremony();
        var response = ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, Payment(total: new { currency = "USD" })));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(response, Expectations()));

        Assert.Equal(Fido2ErrorCode.MalformedAuthenticatorResponse, ex.Code);
    }

    [Fact]
    public async Task Payment_member_is_required_for_a_payment_assertion()
    {
        var ceremony = new Ceremony();
        var response = ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, payment: null));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(response, Expectations()));

        Assert.Equal(Fido2ErrorCode.InvalidPaymentData, ex.Code);
        Assert.Contains("no payment member", ex.Message);
    }

    [Theory]
    [InlineData("10.00", "10")]
    [InlineData("10.0", "10.00")]
    [InlineData("0010.00", "10")]
    public async Task Amounts_compare_as_numbers_and_currencies_regardless_of_case(string signed, string expected)
    {
        var ceremony = new Ceremony();
        var response = ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, Payment(total: new { currency = "usd", value = signed })));

        var expectations = new SecurePaymentConfirmationExpectations
        {
            TopOrigin = MerchantOrigin,
            PayeeOrigin = MerchantOrigin,
            Total = new PaymentCurrencyAmount { Currency = "USD", Value = expected },
            Instrument = Expectations().Instrument,
        };

        await ceremony.VerifyAsync(response, expectations);
    }

    [Fact]
    public async Task Origins_compare_as_origins_and_rpId_regardless_of_case()
    {
        var ceremony = new Ceremony();
        var response = ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, Payment(rpId: "Bank.Example", topOrigin: "https://merchant.example:443", payeeOrigin: "https://merchant.example/")));

        await ceremony.VerifyAsync(response, Expectations());
    }

    [Fact]
    public async Task Rp_is_accepted_in_place_of_rpId_when_they_agree_or_rpId_is_absent()
    {
        var ceremony = new Ceremony();

        await ceremony.VerifyAsync(ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, Payment(rp: RpId))), Expectations());
        await ceremony.VerifyAsync(ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, Payment(rpId: null, rp: RpId))), Expectations());
    }

    private static (string EncodedKey, byte[] CoseKey, ECDsa Key) BrowserBoundKey()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var q = key.ExportParameters(false).Q;
        byte[] coseKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, q.X, q.Y).GetBytes();

        return (Base64Url.EncodeToString(coseKey), coseKey, key);
    }

    private static AuthenticationExtensionsClientOutputs BrowserBoundSignature(ECDsa key, byte[] clientDataJson) => new()
    {
        Payment = new AuthenticationExtensionsPaymentOutputs
        {
            BrowserBoundSignature = new BrowserBoundSignature { Signature = key.SignData(clientDataJson, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence) },
        },
    };

    [Fact]
    public async Task Browser_bound_key_is_returned_when_its_signature_over_the_client_data_verifies()
    {
        var ceremony = new Ceremony();
        var (encodedKey, coseKey, key) = BrowserBoundKey();

        byte[] clientDataJson = ceremony.ClientDataJson("payment.get", RpOrigin, Payment(browserBoundPublicKey: encodedKey));
        var result = await ceremony.VerifyAsync(ceremony.Assert(clientDataJson, BrowserBoundSignature(key, clientDataJson)), Expectations());

        Assert.Equal(coseKey, result.BrowserBoundPublicKey);
    }

    [Fact]
    public async Task Browser_bound_signature_by_another_key_is_refused()
    {
        var ceremony = new Ceremony();
        var (encodedKey, _, _) = BrowserBoundKey();
        var (_, _, otherKey) = BrowserBoundKey();

        byte[] clientDataJson = ceremony.ClientDataJson("payment.get", RpOrigin, Payment(browserBoundPublicKey: encodedKey));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(ceremony.Assert(clientDataJson, BrowserBoundSignature(otherKey, clientDataJson)), Expectations()));

        Assert.Equal(Fido2ErrorCode.InvalidPaymentData, ex.Code);
        Assert.Contains("browser-bound signature does not verify", ex.Message);
    }

    [Fact]
    public async Task Browser_bound_key_and_signature_must_come_together()
    {
        var ceremony = new Ceremony();
        var (encodedKey, _, key) = BrowserBoundKey();

        // Key without signature
        byte[] withKey = ceremony.ClientDataJson("payment.get", RpOrigin, Payment(browserBoundPublicKey: encodedKey));
        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(ceremony.Assert(withKey), Expectations()));
        Assert.Contains("no browser-bound signature", ex.Message);

        // Signature without key
        byte[] withoutKey = ceremony.ClientDataJson("payment.get", RpOrigin, Payment());
        ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(ceremony.Assert(withoutKey, BrowserBoundSignature(key, withoutKey)), Expectations()));
        Assert.Contains("no browser-bound public key", ex.Message);

        // A key that is not a COSE_Key: not CBOR at all, then a CBOR map without the key's members
        foreach (byte[] notAKey in new[] { "not a key"u8.ToArray(), new byte[] { 0xa0 } })
        {
            byte[] garbageKey = ceremony.ClientDataJson("payment.get", RpOrigin, Payment(browserBoundPublicKey: Base64Url.EncodeToString(notAKey)));
            ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(ceremony.Assert(garbageKey, BrowserBoundSignature(key, garbageKey)), Expectations()));
            Assert.Contains("not a valid base64url-encoded COSE_Key", ex.Message);
        }

        // A signature that is not a signature
        byte[] withGoodKey = ceremony.ClientDataJson("payment.get", RpOrigin, Payment(browserBoundPublicKey: encodedKey));
        var garbageSignature = new AuthenticationExtensionsClientOutputs { Payment = new AuthenticationExtensionsPaymentOutputs { BrowserBoundSignature = new BrowserBoundSignature { Signature = [1, 2, 3] } } };
        await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(ceremony.Assert(withGoodKey, garbageSignature), Expectations()));
    }

    [Fact]
    public async Task Logos_are_refused_when_none_were_offered()
    {
        var ceremony = new Ceremony();
        var response = ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, Payment(logos: new[] { new { url = Logo("a").Url, label = "a" } })));

        var expectations = new SecurePaymentConfirmationExpectations
        {
            TopOrigin = MerchantOrigin,
            PayeeOrigin = MerchantOrigin,
            Total = Expectations().Total,
            Instrument = Expectations().Instrument,
            PaymentEntitiesLogos = null,
        };

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(response, expectations));
        Assert.Contains("paymentEntitiesLogos", ex.Message);
    }

    [Fact]
    public async Task Amounts_that_are_not_decimal_strings_compare_as_text()
    {
        // Not valid Payment Request amounts, but the comparison must still be exact rather than lenient
        var ceremony = new Ceremony();

        var expectations = new SecurePaymentConfirmationExpectations
        {
            TopOrigin = MerchantOrigin,
            PayeeOrigin = MerchantOrigin,
            Total = new PaymentCurrencyAmount { Currency = "USD", Value = "10,00" },
            Instrument = Expectations().Instrument,
        };

        await ceremony.VerifyAsync(ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, Payment(total: new { currency = "USD", value = "10,00" }))), expectations);
        await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, Payment(total: new { currency = "USD", value = "10.00" }))), expectations));
    }

    [Fact]
    public async Task Client_data_of_any_other_type_is_refused_by_both_ceremonies()
    {
        var ceremony = new Ceremony();
        var response = ceremony.Assert(ceremony.ClientDataJson("payment.create", RpOrigin, Payment()));

        var ex = await Assert.ThrowsAsync<Fido2VerificationException>(() => ceremony.VerifyAsync(response, Expectations()));

        Assert.Equal(Fido2ErrorCode.InvalidAuthenticatorResponse, ex.Code);
        Assert.Contains("'webauthn.create', 'webauthn.get' or 'payment.get'", ex.Message);
    }

    [Fact]
    public async Task The_original_VerifyAsync_signature_still_works_and_refuses_payments()
    {
        var ceremony = new Ceremony();
        var config = new Fido2Configuration { RPID = RpId, RPName = "Bank", Origins = new HashSet<string> { RpOrigin } };
        var options = new AssertionOptions { Challenge = ceremony.Challenge, RpId = RpId, AllowCredentials = [new PublicKeyCredentialDescriptor(s_credentialId)] };

        var login = AuthenticatorAssertionResponse.Parse(ceremony.Assert(ceremony.ClientDataJson("webauthn.get", RpOrigin, payment: null)));
        var result = await login.VerifyAsync(options, config, ceremony.PublicKey.GetBytes(), 0, (_, _) => Task.FromResult(true), null, null);
        Assert.Equal(s_credentialId, result.CredentialId);

        var payment = AuthenticatorAssertionResponse.Parse(ceremony.Assert(ceremony.ClientDataJson("payment.get", RpOrigin, Payment())));
        await Assert.ThrowsAsync<Fido2VerificationException>(() => payment.VerifyAsync(options, config, ceremony.PublicKey.GetBytes(), 0, (_, _) => Task.FromResult(true), null, null));
    }

    [Fact]
    public async Task Registration_returns_the_browser_bound_key_when_the_browser_supplies_one()
    {
        // A credential created for payments (extensions.payment.isPayment) may register a browser-bound key alongside
        var ceremony = new Ceremony();
        var (encodedKey, coseKey, key) = BrowserBoundKey();

        byte[] clientDataJson = ceremony.ClientDataJson("webauthn.create", RpOrigin, new Dictionary<string, object?> { ["browserBoundPublicKey"] = encodedKey });
        var attestationObject = new CborMap
        {
            { "fmt", "none" },
            { "attStmt", new CborMap() },
            { "authData", new AuthenticatorData(SHA256.HashData(Encoding.UTF8.GetBytes(RpId)), AuthenticatorFlags.AT | AuthenticatorFlags.UP | AuthenticatorFlags.UV, 0, new AttestedCredentialData(Guid.Empty, s_credentialId, ceremony.PublicKey), null).ToByteArray() },
        };

        var response = new AuthenticatorAttestationRawResponse
        {
            Id = Base64Url.EncodeToString(s_credentialId),
            RawId = s_credentialId,
            Type = PublicKeyCredentialType.PublicKey,
            ClientExtensionResults = BrowserBoundSignature(key, clientDataJson),
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = attestationObject.Encode(),
                ClientDataJson = clientDataJson,
                Transports = [AuthenticatorTransport.Internal],
            },
        };

        var fido2 = new Fido2(new Fido2Configuration { RPID = RpId, RPName = "Bank", Origins = new HashSet<string> { RpOrigin } });
        var options = fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User { Id = "user"u8.ToArray(), Name = "user", DisplayName = "User" },
            AuthenticatorSelection = new AuthenticatorSelection { AuthenticatorAttachment = AuthenticatorAttachment.Platform, ResidentKey = ResidentKeyRequirement.Required, UserVerification = UserVerificationRequirement.Required },
            Extensions = new AuthenticationExtensionsClientInputs { Payment = new AuthenticationExtensionsPaymentInputs { IsPayment = true } },
        });
        options.Challenge = ceremony.Challenge;

        var credential = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = response,
            OriginalOptions = options,
            IsCredentialIdUniqueToUserCallback = (_, _) => Task.FromResult(true),
        });

        Assert.Equal(coseKey, credential.BrowserBoundPublicKey);
        Assert.Contains("\"payment\":{\"isPayment\":true}", options.ToJson());
    }

    [Fact]
    public void Payment_extension_input_and_output_serialize_by_their_wire_names()
    {
        var inputs = new AuthenticationExtensionsClientInputs
        {
            Payment = new AuthenticationExtensionsPaymentInputs { IsPayment = true, BrowserBoundPubKeyCredParams = [PubKeyCredParam.ES256] },
        };

        string json = JsonSerializer.Serialize(inputs);
        Assert.Contains("\"payment\":{\"isPayment\":true,\"browserBoundPubKeyCredParams\":[{\"type\":\"public-key\",\"alg\":-7}]}", json);

        var outputs = JsonSerializer.Deserialize<AuthenticationExtensionsClientOutputs>("""{"payment":{"browserBoundSignature":{"signature":"AQID"}}}""");
        Assert.Equal(new byte[] { 1, 2, 3 }, outputs!.Payment!.BrowserBoundSignature!.Signature);

        // Nothing is emitted for a ceremony that is not a payment
        Assert.DoesNotContain("payment", JsonSerializer.Serialize(new AuthenticationExtensionsClientInputs()));
        Assert.DoesNotContain("payment", JsonSerializer.Serialize(new AuthenticationExtensionsClientOutputs()));
    }

    [Fact]
    public void Client_data_carries_the_payment_member_as_the_browser_signs_it()
    {
        var response = JsonSerializer.Deserialize<AuthenticatorResponse>("""
            {"type":"payment.get","challenge":"AQID","origin":"https://bank.example",
             "payment":{"rpId":"bank.example","topOrigin":"https://merchant.example","payeeOrigin":"https://merchant.example",
                        "paymentEntitiesLogos":[{"url":"https://logos.example/a.png","label":"a"}],
                        "total":{"currency":"USD","value":"10.00"},
                        "instrument":{"displayName":"Visa ****1234","icon":"https://bank.example/card.png","iconMustBeShown":true},
                        "browserBoundPublicKey":"pQECAyY"}}
            """)!;

        var payment = response.Payment!;
        Assert.Equal("bank.example", payment.RpId);
        Assert.Equal("https://merchant.example", payment.TopOrigin);
        Assert.Equal("https://merchant.example", payment.PayeeOrigin);
        Assert.Null(payment.PayeeName);
        Assert.Equal("a", Assert.Single(payment.PaymentEntitiesLogos!).Label);
        Assert.Equal("USD", payment.Total!.Currency);
        Assert.Equal("10.00", payment.Total.Value);
        Assert.Equal("Visa ****1234", payment.Instrument!.DisplayName);
        Assert.True(payment.Instrument.IconMustBeShown);
        Assert.Equal("pQECAyY", payment.BrowserBoundPublicKey);
    }
}
