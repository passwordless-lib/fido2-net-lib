using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

namespace Fido2Demo
{
    public static class RouteHelperExtensions
    {
        public static RewriteOptions AddRedirectToWWwIfPasswordlessDomain(this RewriteOptions options)
        {
            options.Add(new RedirectToWWwIfPasswordlessDomainRule());
            return options;
        }

        public class RedirectToWWwIfPasswordlessDomainRule : IRule
        {
            public virtual void ApplyRule(RewriteContext context)
            {
                var req = context.HttpContext.Request;
                if (req.Host.Host.Equals("passwordless.dev"))
                {
                    var wwwHost = new HostString($"www.{req.Host.Value}");
                    var newUrl = UriHelper.BuildAbsolute(req.Scheme, wwwHost, req.PathBase, req.Path, req.QueryString);
                    var response = context.HttpContext.Response;
                    response.StatusCode = 301;
                    response.Headers[HeaderNames.Location] = newUrl;
                    context.Result = RuleResult.EndResponse;
                }else if(req.Host.Equals("fido2.azurewebsites.net"))
                {
                    var wwwHost = new HostString($"www.passwordless.dev");
                    var newUrl = UriHelper.BuildAbsolute("https", wwwHost, req.PathBase, req.Path, req.QueryString);
                    var response = context.HttpContext.Response;
                    response.StatusCode = 301;
                    response.Headers[HeaderNames.Location] = newUrl;
                    context.Result = RuleResult.EndResponse;
                }

                context.Result = RuleResult.ContinueRules;
                return;
            }
        }
    }

}

