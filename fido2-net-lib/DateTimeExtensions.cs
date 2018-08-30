using System;

namespace Fido2NetLib
{
   internal static class DateTimeHelper
    {
        private static readonly DateTime _unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        internal static DateTime UnixEpoch
        {
            get { return _unixEpoch; }
        }
    }
}
