using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Fido2NetLib;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json.Converters;

namespace Fido2Demo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }
        public IRule PasswordLessDomainRule { get; private set; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services
                .AddMvc(options => { options.EnableEndpointRouting = false; })
                .AddNewtonsoftJson()
                .AddRazorPagesOptions(o =>
            {
                // we don't care about antiforgery in the demo
                o.Conventions.ConfigureFilter(new IgnoreAntiforgeryTokenAttribute());
            });

            // Adds a default in-memory implementation of IDistributedCache.
            services.AddDistributedMemoryCache();
            services.AddSession(options =>
            {
                // Set a short timeout for easy testing.
                options.IdleTimeout = TimeSpan.FromMinutes(2);
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.None;
            });

            services.AddFido2(options =>
            {
                options.ServerDomain = Configuration["fido2:serverDomain"];
                options.ServerName = "FIDO2 Test";
                options.Origin = Configuration["fido2:origin"];
                options.TimestampDriftTolerance = Configuration.GetValue<int>("fido2:timestampDriftTolerance");
                options.MDSAccessKey = Configuration["fido2:MDSAccessKey"];
                options.MDSCacheDirPath = Configuration["fido2:MDSCacheDirPath"];
            })
            .AddCachedMetadataService(config =>
            {
                //They'll be used in a "first match wins" way in the order registered
                config.AddStaticMetadataRepository();
                if (!string.IsNullOrWhiteSpace(Configuration["fido2:MDSAccessKey"]))
                {
                    config.AddFidoMetadataRepository(Configuration["fido2:MDSAccessKey"]);
                }
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                //app.UseBrowserLink();
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseRewriter(new RewriteOptions().AddRedirectToWWwIfPasswordlessDomain());
            }

            app.UseSession();
            app.UseRewriter(new RewriteOptions().Add(rewriteContext =>
            {
                var request = rewriteContext.HttpContext.Request;
                if (request.Path == new PathString("/"))
                {
                    rewriteContext.HttpContext.Response.Redirect(request.PathBase + "/overview", true);
                    rewriteContext.Result = RuleResult.EndResponse;
                }
            }));
            app.UseMvc();
            app.UseStaticFiles();
        }
    }
}
