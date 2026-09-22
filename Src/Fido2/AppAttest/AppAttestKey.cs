using System.Security.Cryptography.X509Certificates;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// An App Attest key the app has proven it holds: what to store after a successful attestation, and what to bring
/// back to verify each assertion. Keep <see cref="Counter"/> up to date from every verified assertion.
/// </summary>
public sealed class AppAttestKey
{
    /// <summary>
    /// The key identifier the app reports: the SHA-256 hash of the public key, which the app uses to name the key.
    /// </summary>
    public required byte[] KeyId { get; init; }

    /// <summary>
    /// The public key as a COSE_Key, which every assertion is verified with.
    /// </summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// The counter from the last verified attestation or assertion. An assertion whose counter is not higher is
    /// refused, which catches replays and cloned keys.
    /// </summary>
    public required uint Counter { get; init; }

    /// <summary>
    /// The environment the key was created in.
    /// </summary>
    public required AppAttestEnvironment Environment { get; init; }

    /// <summary>
    /// The receipt Apple issued with the attestation, for requesting a fraud assessment from Apple's servers. The
    /// library does not interpret it.
    /// </summary>
    public byte[]? Receipt { get; init; }
}

/// <summary>
/// The outcome of a verified App Attest attestation.
/// </summary>
public sealed class AppAttestAttestationResult
{
    /// <summary>
    /// The key to store.
    /// </summary>
    public required AppAttestKey Key { get; init; }

    /// <summary>
    /// The kind of attestation the statement established.
    /// </summary>
    public required AttestationType AttestationType { get; init; }

    /// <summary>
    /// The attestation certificate followed by Apple's intermediate, as the app supplied them.
    /// </summary>
    public required X509Certificate2[] TrustPath { get; init; }
}

/// <summary>
/// The outcome of a verified App Attest assertion.
/// </summary>
public sealed class AppAttestAssertionResult
{
    /// <summary>
    /// The counter the assertion carried, which is now the key's counter.
    /// </summary>
    public required uint Counter { get; init; }

    /// <summary>
    /// The key as it should now be stored: the same key with <see cref="AppAttestKey.Counter"/> advanced.
    /// </summary>
    public required AppAttestKey Key { get; init; }
}
