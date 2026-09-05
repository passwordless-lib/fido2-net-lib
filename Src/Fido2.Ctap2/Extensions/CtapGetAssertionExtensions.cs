using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// Typed authenticator extension inputs for the <c>extensions</c> field (0x04) of an
/// authenticatorGetAssertion request, covering the CTAP-defined extensions from §12 of the
/// CTAP 2.3 Proposed Standard.
/// </summary>
public sealed class CtapGetAssertionExtensions
{
    /// <summary>
    /// Requests retrieval of the credBlob value stored with the credential. Sent as
    /// <c>"credBlob": true</c>.
    /// </summary>
    public bool? CredBlob { get; init; }

    /// <summary>
    /// Requests one or two hmac-secret outputs, encrypted and authenticated per §12.7.
    /// </summary>
    public HmacSecretInput? HmacSecret { get; init; }

    /// <summary>
    /// Requests the credential's largeBlobKey, if any, in the top-level response (not the
    /// authenticator data's extensions field). Sent as <c>"largeBlobKey": true</c>.
    /// </summary>
    public bool? LargeBlobKey { get; init; }

    /// <summary>
    /// Requests whether the credential is third-party-payment enabled. Sent as
    /// <c>"thirdPartyPayment": true</c>.
    /// </summary>
    public bool? ThirdPartyPayment { get; init; }

    /// <summary>
    /// Additional, e.g. vendor-specific or not-yet-modeled, extension entries to merge in verbatim.
    /// </summary>
    public CborMap? AdditionalExtensions { get; init; }

    internal CborMap? ToCborObject()
    {
        var result = new CborMap();

        if (CredBlob.HasValue)
        {
            result.Add("credBlob", (CborObject)(CborBoolean)CredBlob.Value);
        }

        if (HmacSecret != null)
        {
            result.Add("hmac-secret", HmacSecret.ToCborObject());
        }

        if (LargeBlobKey.HasValue)
        {
            result.Add("largeBlobKey", (CborObject)(CborBoolean)LargeBlobKey.Value);
        }

        if (ThirdPartyPayment.HasValue)
        {
            result.Add("thirdPartyPayment", (CborObject)(CborBoolean)ThirdPartyPayment.Value);
        }

        if (AdditionalExtensions != null)
        {
            foreach (var (key, value) in AdditionalExtensions)
            {
                result.Add((string)key, value);
            }
        }

        return result.Count > 0 ? result : null;
    }
}
