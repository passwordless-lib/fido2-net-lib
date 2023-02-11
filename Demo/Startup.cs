using System;
using System.Collections.Generic;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Fido2Demo;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddRazorPages(opts =>
        {
            // we don't care about antiforgery in the demo
            opts.Conventions.ConfigureFilter(new IgnoreAntiforgeryTokenAttribute());
        });

        // Use the in-memory implementation of IDistributedCache.
        services.AddMemoryCache();
        services.AddDistributedMemoryCache();

        services.AddSession(options =>
        {
            // Set a short timeout for easy testing.
            options.IdleTimeout = TimeSpan.FromMinutes(2);
            options.Cookie.HttpOnly = true;
            // Strict SameSite mode is required because the default mode used
            // by ASP.NET Core 3 isn't understood by the Conformance Tool
            // and breaks conformance testing
            options.Cookie.SameSite = SameSiteMode.Unspecified;
        });

        services.AddFido2(options =>
        {
            options.ServerDomain = Configuration["fido2:serverDomain"];
            options.ServerName = "FIDO2 Test";
            options.Origins = Configuration.GetSection("fido2:origins").Get<HashSet<string>>();
            options.TimestampDriftTolerance = Configuration.GetValue<int>("fido2:timestampDriftTolerance");
            options.MDSCacheDirPath = Configuration["fido2:MDSCacheDirPath"];
            options.AllowBackupEligibleCredential = Configuration.GetValue<bool>("fido2:allowBackupEligibleCredential");
            options.AllowBackedUpCredential = Configuration.GetValue<bool>("fido2:allowBackedUpCredential");
        })
        .AddCachedMetadataService(config =>
        {
            config.AddFidoMetadataRepository(httpClientBuilder =>
            {
                //TODO: any specific config you want for accessing the MDS
            });
        });
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseRewriter(new RewriteOptions().AddRedirectToWWwIfPasswordlessDomain());
        }

        app.UseSession();
        app.UseStaticFiles();
        app.UseRouting();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapFallbackToPage("/", "/overview");
            endpoints.MapRazorPages();
            endpoints.MapControllers();
        });
    }
}
