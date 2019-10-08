using System;

namespace Fido2NetLib
{
   internal static class DateTimeHelper
    {
        internal static DateTime UnixEpoch { get; } = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    }
}
