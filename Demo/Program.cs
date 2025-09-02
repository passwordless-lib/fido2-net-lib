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
    options.ServerDomain = builder.Configuration["fido2:serverDomain"];
    options.ServerName = "FIDO2 Test";
    options.Origins = builder.Configuration.GetSection("fido2:origins").Get<HashSet<string>>();
    options.TimestampDriftTolerance = builder.Configuration.GetValue<int>("fido2:timestampDriftTolerance");
    options.MDSCacheDirPath = builder.Configuration["fido2:MDSCacheDirPath"];
    options.BackupEligibleCredentialPolicy = builder.Configuration.GetValue<Fido2Configuration.CredentialBackupPolicy>("fido2:backupEligibleCredentialPolicy");
    options.BackedUpCredentialPolicy = builder.Configuration.GetValue<Fido2Configuration.CredentialBackupPolicy>("fido2:backedUpCredentialPolicy");
})
.AddCachedMetadataService(config =>
{
    config.AddFidoMetadataRepository(httpClientBuilder =>
    {
        //TODO: any specific config you want for accessing the MDS
    });
});

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

app.UseSession();
app.UseStaticFiles();
app.UseRouting();

app.MapFallbackToPage("/", "/overview");
app.MapRazorPages();
app.MapControllers();

app.Run();
