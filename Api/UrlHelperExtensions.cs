using Microsoft.AspNetCore.Mvc;

namespace Fido2Api;

public static class UrlHelperExtensions
{
    public static string ToGithub(this IUrlHelper url, string path)
    {
        return "https://github.com/abergs/fido2-net-lib/blob/master/" + path;
    }
}
