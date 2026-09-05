using Fido2NetLib;
using Fido2NetLib.Serialization;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for serving the <c>/.well-known/webauthn</c> resource used to validate
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">related origin requests</see>.
/// </summary>
public static class WellKnownWebAuthnEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps a GET endpoint at <c>/.well-known/webauthn</c> that serves the RP's configured <see cref="Fido2Configuration.Origins"/>
    /// as JSON, generated from the <see cref="Fido2Configuration"/> registered with dependency injection.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder to add the route to.</param>
    /// <returns>The <see cref="IEndpointConventionBuilder"/> so further customization can be chained.</returns>
    public static IEndpointConventionBuilder MapFido2WellKnownWebAuthn(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapGet("/.well-known/webauthn", (Fido2Configuration config) =>
        {
            return Results.Json(config.GetWellKnownWebAuthn(), FidoModelSerializerContext.Default.WellKnownWebAuthn);
        });
    }
}
