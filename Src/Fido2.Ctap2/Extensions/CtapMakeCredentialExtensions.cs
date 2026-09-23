using Fido2NetLib.Cbor;
using Fido2NetLib.Objects;

namespace Fido2NetLib.Ctap2;

/// <summary>
/// Typed authenticator extension inputs for the <c>extensions</c> field (0x06) of an
/// authenticatorMakeCredential request, covering the CTAP-defined extensions from §12 of the
/// CTAP 2.3 Proposed Standard.
/// </summary>
public sealed class CtapMakeCredentialExtensions
{
    /// <summary>
    /// The credential protection policy to persist with the new credential. Sent as
    /// <c>"credProtect": &lt;value&gt;</c>.
    /// </summary>
    public CredentialProtectionPolicy? CredProtect { get; init; }

    /// <summary>
    /// Opaque, RP-specific data (at most <c>maxCredBlobLength</c> bytes, per authenticatorGetInfo)
    /// to persist with the credential. Sent as <c>"credBlob": &lt;bytes&gt;</c>.
    /// </summary>
    public byte[]? CredBlob { get; init; }

    /// <summary>
    /// Requests that the authenticator associate an hmac-secret with the new credential. Sent as
    /// <c>"hmac-secret": true</c>.
    /// </summary>
    public bool? HmacSecret { get; init; }

    /// <summary>
    /// Requests an hmac-secret output at creation time (§12.8). <see cref="HmacSecret"/> MUST also
    /// be set to <c>true</c> when this is present.
    /// </summary>
    public HmacSecretInput? HmacSecretMc { get; init; }

    /// <summary>
    /// Requests the current minimum PIN length value, if this RP is authorized to receive it.
    /// Sent as <c>"minPinLength": true</c>.
    /// </summary>
    public bool? MinPinLength { get; init; }

    /// <summary>
    /// Requests the current PIN complexity policy value, if this RP is authorized to receive it.
    /// Sent as <c>"pinComplexityPolicy": true</c>.
    /// </summary>
    public bool? PinComplexityPolicy { get; init; }

    /// <summary>
    /// Requests that the authenticator generate and associate a largeBlobKey with the new
    /// (discoverable) credential. Sent as <c>"largeBlobKey": true</c>.
    /// </summary>
    public bool? LargeBlobKey { get; init; }

    /// <summary>
    /// Marks the credential as usable for third-party payment authentication. Sent as
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

        if (CredProtect.HasValue)
        {
            result.Add("credProtect", (int)CredProtect.Value);
        }

        if (CredBlob != null)
        {
            result.Add("credBlob", CredBlob);
        }

        if (HmacSecret.HasValue)
        {
            result.Add("hmac-secret", (CborObject)(CborBoolean)HmacSecret.Value);
        }

        if (HmacSecretMc != null)
        {
            result.Add("hmac-secret-mc", HmacSecretMc.ToCborObject());
        }

        if (MinPinLength.HasValue)
        {
            result.Add("minPinLength", (CborObject)(CborBoolean)MinPinLength.Value);
        }

        if (PinComplexityPolicy.HasValue)
        {
            result.Add("pinComplexityPolicy", (CborObject)(CborBoolean)PinComplexityPolicy.Value);
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
