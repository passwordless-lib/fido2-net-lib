using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.Net.Http.Headers;

namespace Fido2Demo;

public static class RouteHelperExtensions
{
    public static RewriteOptions AddRedirectToWWwIfPasswordlessDomain(this RewriteOptions options)
    {
        options.Add(new RedirectToWwwIfPasswordlessDomainRule());
        return options;
    }

    public class RedirectToWwwIfPasswordlessDomainRule : IRule
    {
        public virtual void ApplyRule(RewriteContext context)
        {
            var req = context.HttpContext.Request;
            if (req.Host.Host is "fido2.azurewebsites.net")
            {
                var wwwHost = new HostString("fido2.andersaberg.com");
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
