using System;
using System.Collections.Generic;

using Fido2NetLib.Cbor;
using Fido2NetLib.Exceptions;

namespace Fido2NetLib.Objects;

/// <summary>
/// The raw extensions block of the authenticator data: a CBOR map of extension identifier to authenticator
/// extension output.
/// </summary>
/// <remarks>
/// Use <see cref="Outputs"/> for the outputs CTAP defines, decoded into typed values, and
/// <see cref="GetBytes"/> to read anything this library does not model.
/// </remarks>
public sealed class Extensions
{
    private readonly byte[] _extensionBytes;

    private CborMap? _values;
    private bool _decoded;
    private Exception? _decodeFailure;

    private AuthenticationExtensionsAuthenticatorOutputs? _outputs;

    public Extensions(byte[] extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);

        _extensionBytes = extensions;
    }

    public int Length => _extensionBytes.Length;

    public byte[] GetBytes()
    {
        return _extensionBytes;
    }

    /// <summary>
    /// The authenticator extension outputs, decoded into the outputs CTAP defines. Every member is
    /// <see langword="null"/> when the authenticator did not return that extension, when its value had the
    /// wrong CBOR type, or when this block did not decode at all -- a malformed block is only reported as an
    /// error where the Relying Party asked for the outputs to be validated, see
    /// <see cref="UnsolicitedExtensionPolicy"/>.
    /// </summary>
    public AuthenticationExtensionsAuthenticatorOutputs Outputs => _outputs ??= DecodeOutputs();

    /// <summary>
    /// The decoded extension map, or <see langword="null"/> when the block is empty or does not decode to a
    /// CBOR map. Decoding happens once, on first use, and the outcome is cached.
    /// </summary>
    private CborMap? Values
    {
        get
        {
            if (!_decoded)
            {
                _decoded = true;

                if (_extensionBytes.Length > 0)
                {
                    try
                    {
                        _values = (CborMap)CborObject.Decode(_extensionBytes);
                    }
                    catch (Exception ex)
                    {
                        _decodeFailure = ex;
                    }
                }
            }

            return _values;
        }
    }

    private AuthenticationExtensionsAuthenticatorOutputs DecodeOutputs()
    {
        var values = Values;

        if (values is null)
            return new AuthenticationExtensionsAuthenticatorOutputs();

        return new AuthenticationExtensionsAuthenticatorOutputs
        {
            // "credProtect": <credProtect Value>, one of the three policies CTAP defines.
            CredProtect = values["credProtect"] is CborInteger { Value: >= 0x01 and <= 0x03 } credProtect
                ? (CredentialProtectionPolicy)credProtect.Value
                : null,

            // "credBlob" is a boolean on a registration (was it stored?) and a byte string on an assertion
            // (here it is), so the two shapes are reported separately.
            CredBlobStored = values["credBlob"] is CborBoolean credBlobStored ? credBlobStored.Value : null,
            CredBlob = values["credBlob"] is CborByteString credBlob ? credBlob.Value : null,

            // "minPinLength": uint
            MinPinLength = values["minPinLength"] is CborInteger { Value: >= 0 and <= uint.MaxValue } minPinLength
                ? (uint)minPinLength.Value
                : null,

            // "pinComplexityPolicy": boolean
            PinComplexityPolicy = values["pinComplexityPolicy"] is CborBoolean pinComplexityPolicy ? pinComplexityPolicy.Value : null,

            // "thirdPartyPayment": boolean
            ThirdPartyPayment = values["thirdPartyPayment"] is CborBoolean thirdPartyPayment ? thirdPartyPayment.Value : null,

            // On a registration "hmac-secret" is a boolean saying whether the credential has one. On an
            // assertion it is the encrypted salt outputs, which only the client can decrypt, so there is
            // nothing here for the Relying Party to read.
            HmacSecret = values["hmac-secret"] is CborBoolean hmacSecret ? hmacSecret.Value : null
        };
    }

    /// <summary>
    /// The extension identifiers present in the authenticator extension outputs.
    /// </summary>
    /// <exception cref="Fido2VerificationException">
    /// Thrown when the extensions block does not decode to a CBOR map.
    /// </exception>
    internal HashSet<string> GetIdentifiers()
    {
        var identifiers = new HashSet<string>(StringComparer.Ordinal);

        var values = Values;

        if (_decodeFailure is not null)
        {
            throw new Fido2VerificationException(
                Fido2ErrorCode.MalformedExtensionsDetected,
                "Failed to decode authenticator extensions from authData",
                _decodeFailure);
        }

        if (values is null)
            return identifiers;

        foreach (var key in values.Keys)
        {
            // CBOR map keys are text strings (extension identifiers). CTAP does not define any other key type
            // here, so anything else is simply not an identifier we can report.
            if (key is CborTextString extensionId)
            {
                identifiers.Add(extensionId);
            }
        }

        return identifiers;
    }
}
