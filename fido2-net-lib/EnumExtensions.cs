using System;

namespace Fido2NetLib
{
    public static class EnumExtensions
    {
        public static T ParseEnum<T>(string inString, bool ignoreCase = true, bool throwException = true) where T : struct
        {
            return (T)ParseEnum<T>(inString, default(T), ignoreCase, throwException);
        }

        public static T ParseEnum<T>(string inString, T defaultValue, bool ignoreCase = true, bool throwException = false) where T : struct
        {
            T returnEnum = defaultValue;

            if (!typeof(T).IsEnum || string.IsNullOrEmpty(inString))
            {
                throw new InvalidOperationException("Invalid Enum Type or Input String 'inString'. " + typeof(T).ToString() + " must be an Enum");
            }

            try
            {
                bool success = Enum.TryParse<T>(inString, ignoreCase, out returnEnum);
                if (!success && throwException)
                {
                    throw new InvalidOperationException("Invalid Cast");
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Invalid Cast", ex);
            }

            return returnEnum;
        }

        public static T ToEnum<T>(this string inString, bool ignoreCase = true, bool throwException = true) where T : struct
        {
            return (T)ParseEnum<T>(inString, ignoreCase, throwException);
        }

        public static T ToEnum<T>(this string inString, T defaultValue, bool ignoreCase = true, bool throwException = false) where T : struct
        {
            return (T)ParseEnum<T>(inString, defaultValue, ignoreCase, throwException);
        }
    }
}
