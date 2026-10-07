using System.Collections.Immutable;
using System.Reflection;
using System.Runtime.CompilerServices;

using Fido2NetLib.Objects;

namespace Fido2NetLib;

/// <summary>
/// The registered <see cref="IOkpSignatureVerifier"/>s consulted for COSE OKP (EdDSA) credentials.
/// </summary>
/// <remarks>
/// A package that implements a provider (e.g. <c>Fido2.NSec</c>) registers it once, automatically, via a
/// <see langword="[ModuleInitializer]"/> in its own assembly -- nothing to configure in your own startup code.
/// That only runs once the runtime actually initializes the assembly's module, though, and nothing in
/// <c>Fido2</c> core references a <c>Fido2.NSec</c> type by name (deliberately: doing so would make
/// <c>Fido2.WithoutNSec</c>, which omits that reference, fail to compile from the same source) -- so nothing
/// would otherwise ever trigger that initialization. This class's static constructor closes that gap:
/// a best-effort, name-only <see cref="Assembly.Load(string)"/> of <c>Fido2.NSec</c>, followed by
/// <see cref="RuntimeHelpers.RunModuleConstructor"/> to force its module initializer to run (loading alone
/// does not -- the runtime otherwise defers that until something in the module is actually touched, which
/// nothing here ever does). Present and succeeds when <c>Fido2</c> (the default) pulled it in transitively;
/// absent and silently skipped under <c>Fido2.WithoutNSec</c>, or if this process never referenced either
/// package at all. Registration is additive and append-only by design: there is no unregister, since
/// providers are meant to be assembly-level facts ("this process has NSec.Cryptography loaded"), not
/// something toggled at runtime.
/// </remarks>
public static class OkpSignatureVerifiers
{
    private static ImmutableArray<IOkpSignatureVerifier> _verifiers = [];

    /// <summary>
    /// The exception from the most recent failed attempt to load and initialize <c>Fido2.NSec</c>, or
    /// <see langword="null"/> if the last attempt succeeded or failed for the expected reason (the assembly
    /// simply isn't referenced, as under <c>Fido2.WithoutNSec</c>).
    /// </summary>
    /// <remarks>
    /// This is diagnostic only: nothing in this library reads it, and a non-<see langword="null"/> value does
    /// not change how <see cref="Find"/> behaves (no provider ends up registered either way). It exists so a
    /// host that expected EdDSA support to be present -- i.e. referenced <c>Fido2</c>, not
    /// <c>Fido2.WithoutNSec</c> -- can tell "the dependency genuinely isn't there" apart from "it's there but
    /// broke while loading," which would otherwise both silently present as "no provider registered."
    /// </remarks>
    public static Exception? BootstrapError { get; private set; }

    static OkpSignatureVerifiers()
    {
        try
        {
            var assembly = Assembly.Load("Fido2.NSec");
            RuntimeHelpers.RunModuleConstructor(assembly.ManifestModule.ModuleHandle);
        }
        catch (Exception ex) when (ex is FileNotFoundException or FileLoadException or BadImageFormatException)
        {
            // Expected: Fido2.NSec isn't referenced (Fido2.WithoutNSec was used instead of Fido2, or this
            // process never referenced either package). Not recorded in BootstrapError -- this is the normal,
            // unremarkable outcome for a correctly-configured Fido2.WithoutNSec consumer.
        }
        catch (Exception ex)
        {
            // Deliberately still catches everything else too, rather than letting it propagate: a static
            // constructor that throws permanently fails the type for the rest of the process (CLR
            // type-initialization semantics wrap it in TypeInitializationException on every later access), so
            // a misbehaving module initializer in Fido2.NSec -- or any other IOkpSignatureVerifier provider
            // this bootstrap is later extended to probe for -- must not be allowed to take down OKP/EdDSA
            // verification process-wide. Worst case here is the same as the expected case: no provider ends
            // up registered, and CredentialPublicKey.Verify reports that with UnimplementedAlgorithm when an
            // OKP credential is actually verified, rather than failing here at class-init time. Recorded in
            // BootstrapError, unlike the expected case above, since this means something unexpected happened
            // to a dependency the host presumably intended to have.
            BootstrapError = ex;
        }
    }

    /// <summary>
    /// Registers a provider. Safe to call from multiple threads or multiple module initializers concurrently.
    /// </summary>
    public static void Register(IOkpSignatureVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(verifier);

        ImmutableInterlocked.Update(ref _verifiers, static (current, v) => current.Add(v), verifier);
    }

    /// <summary>
    /// The first registered provider that can verify <paramref name="curve"/>, or <see langword="null"/> if
    /// none can -- either because nothing implementing that curve is referenced (e.g. <c>Fido2.WithoutNSec</c>
    /// was used instead of <c>Fido2</c>), or because no provider anywhere implements it yet.
    /// </summary>
    public static IOkpSignatureVerifier? Find(COSE.EllipticCurve curve)
    {
        var verifiers = _verifiers;

        foreach (var verifier in verifiers)
        {
            if (verifier.CanVerify(curve))
                return verifier;
        }

        return null;
    }
}
