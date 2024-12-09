using System;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace Fido2NetLib
{
    public static class StringExtensions
    {
        public static string ToFullyQualifiedOrigin(this string origin)
        {
            if (IsWildCardUrl(origin))
            {
                var uri = new Uri(origin.Remove(origin.IndexOf("*."), 2));
                if (UriHostNameType.Unknown != uri.HostNameType)
                    return uri.IsDefaultPort ? $"{uri.Scheme}://*.{uri.Host}" : $"{uri.Scheme}://*.{uri.Host}:{uri.Port}";
            }
            else
            {
                var uri = new Uri(origin);
                if (UriHostNameType.Unknown != uri.HostNameType)
                    return uri.IsDefaultPort ? $"{uri.Scheme}://{uri.Host}" : $"{uri.Scheme}://{uri.Host}:{uri.Port}";
            }

            return origin;
        }

        public static bool ContainsUrl(this IReadOnlySet<string> fullyQualifiedExpectedOrigins, string fullyQualifiedOrigin)
        {
            foreach (var fullyQualifiedExpectedOrigin in fullyQualifiedExpectedOrigins)
            {
                if ((IsWildCardUrl(fullyQualifiedExpectedOrigin) && IsMatch(fullyQualifiedExpectedOrigin, fullyQualifiedOrigin)) || (fullyQualifiedExpectedOrigin.Equals(fullyQualifiedOrigin, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
            return false;
        }

        private static bool IsWildCardUrl(string origin)
        {
            string pattern = @"^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/\*\..*$";
            return Regex.IsMatch(origin, pattern);
        }

        private static bool IsMatch(string wildcardUrl, string testUrl)
        {
            var pattern = "^" + Regex.Escape(wildcardUrl).Replace("\\*", "[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?") + "$";
            return Regex.IsMatch(testUrl, pattern);
        }
    }
}
