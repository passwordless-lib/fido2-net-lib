using System;
using System.Security.Cryptography.X509Certificates;

namespace Fido2NetLib;

/// <summary>
/// Which App Attest environment a key was created in. Apple marks the two with different AAGUIDs, and a
/// development key never carries a receipt Apple's fraud assessment accepts.
/// </summary>
[Flags]
public enum AppAttestEnvironment
{
    /// <summary>
    /// Keys from apps distributed through the App Store, TestFlight or enterprise distribution.
    /// </summary>
    Production = 1,

    /// <summary>
    /// Keys from apps run from Xcode. Their attestation certificates are short-lived and are accepted after expiry.
    /// </summary>
    Development = 2,
}

/// <summary>
/// The settings for verifying Apple App Attest attestations and assertions from one app.
/// </summary>
public sealed class AppAttestConfiguration
{
    /// <summary>
    /// The app's App ID: its 10-character team identifier, a period, and its bundle identifier, such as
    /// <c>ABCDE12345.com.example.app</c>. Its SHA-256 hash is what every attestation and assertion is scoped to.
    /// </summary>
    public required string AppId { get; init; }

    /// <summary>
    /// The environments to accept keys from. Defaults to <see cref="AppAttestEnvironment.Production"/>; include
    /// <see cref="AppAttestEnvironment.Development"/> while testing from Xcode.
    /// </summary>
    public AppAttestEnvironment Environments { get; init; } = AppAttestEnvironment.Production;

    /// <summary>
    /// The root every attestation certificate chain must end at. Defaults to <see cref="AppAttest.AppleRootCertificate"/>.
    /// </summary>
    public X509Certificate2 TrustAnchor { get; init; } = AppAttest.AppleRootCertificate;
}
