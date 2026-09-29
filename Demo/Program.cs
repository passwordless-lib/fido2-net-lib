using Fido2Demo;
using Fido2NetLib;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Rewrite;

var builder = WebApplication.CreateBuilder(args);

// Configure Services
builder.Services.AddRazorPages(opts =>
{
    // we don't care about antiforgery in the demo
    opts.Conventions.ConfigureFilter(new IgnoreAntiforgeryTokenAttribute());
});

// Use the in-memory implementation of IDistributedCache.
builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
    // Set a short timeout for easy testing.
    options.IdleTimeout = TimeSpan.FromMinutes(2);
    options.Cookie.HttpOnly = true;
    // Strict SameSite mode is required because the default mode used
    // by ASP.NET Core 3 isn't understood by the Conformance Tool
    // and breaks conformance testing
    options.Cookie.SameSite = SameSiteMode.Unspecified;
});

builder.Services.AddFido2(options =>
{
    options.RPID = builder.Configuration["fido2:serverDomain"];
    options.RPName = "FIDO2 Test";
    options.Origins = builder.Configuration.GetSection("fido2:origins").Get<HashSet<string>>();

    // Other options available:
    options.TimestampDriftTolerance = builder.Configuration.GetValue<int>("fido2:timestampDriftTolerance");
    options.MDSCacheDirPath = builder.Configuration["fido2:MDSCacheDirPath"];
    options.BackupEligibleCredentialPolicy = builder.Configuration.GetValue<Fido2Configuration.CredentialBackupPolicy>("fido2:backupEligibleCredentialPolicy");
    options.BackedUpCredentialPolicy = builder.Configuration.GetValue<Fido2Configuration.CredentialBackupPolicy>("fido2:backedUpCredentialPolicy");

    // Admin controls: authenticator models to refuse outright (e.g. "aaguidDenyList": [ "<aaguid>" ]), and a
    // re-check of the MDS status at every sign-in, so a model revoked after registration stops working.
    options.AaguidDenyList = builder.Configuration.GetSection("fido2:aaguidDenyList").Get<HashSet<Guid>>() ?? [];
    options.RecheckMetadataStatusOnAssertion = true;

    // Friendly names and icons for passkey providers that have no FIDO Metadata Service statement (most don't).
    options.DisplayMetadata.UseConvenienceMetadataService = builder.Configuration.GetValue("fido2:useConvenienceMetadataService", true);
})
.AddFidoMetadataRepository()
.AddCachedMetadataService()
.AddAuthenticatorDisplayMetadata()
.AddFido2MetadataHealthCheck();

var app = builder.Build();

// Configure Pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseRewriter(new RewriteOptions().AddRedirectToWWwIfPasswordlessDomain());
}

// Enforce HTTPS redirection for all requests
app.UseHttpsRedirection();

// Optional: record conformance-endpoint traffic and the reason for every rejection (see ConformanceTrafficLog.cs)
if (builder.Configuration["conformance:trafficLog"] is { Length: > 0 } trafficLogPath)
{
    app.UseMiddleware<ConformanceTrafficLogMiddleware>(trafficLogPath);
}

app.UseSession();

// Serve the .well-known/webauthn resource for WebAuthn related origin requests,
// generated from the configured Fido2Configuration.Origins.
app.MapFido2WellKnownWebAuthn();

app.UseStaticFiles();

app.UseRouting();

// Unhealthy when no metadata BLOB is available, degraded when refreshes are failing.
app.MapHealthChecks("/health");

app.MapFallbackToPage("/", "/overview");
app.MapRazorPages();
app.MapControllers();

app.Run();
