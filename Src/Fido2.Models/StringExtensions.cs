using System;

namespace Fido2NetLib
{
    public static class StringExtensions
    {
        public static string ToFullyQualifiedOrigin(this string origin)
        {
            var uri = new Uri(origin);

            if (UriHostNameType.Unknown != uri.HostNameType)
                return uri.IsDefaultPort ? $"{uri.Scheme}://{uri.Host}" : $"{uri.Scheme}://{uri.Host}:{uri.Port}";

            return origin;
        }
    }
}
