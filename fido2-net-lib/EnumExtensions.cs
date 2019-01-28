using System;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;

namespace Fido2NetLib
{
    public static class EnumExtensions
    {
        /// <summary>
        /// Gets the enum value from EnumMemberAttribute's value.
        /// </summary>
        /// <typeparam name="TEnum">The type of enum.</typeparam>
        /// <param name="value">The EnumMemberAttribute's value.</param>
        /// <param name="ignoreCase">ignores the case when comparing values.</param>
        /// <returns>TEnum.</returns>
        /// <exception cref="System.ArgumentException">No XmlEnumAttribute code exists for type " + typeof(TEnum).ToString() + " corresponding to value of " + value</exception>
        public static TEnum ToEnum<TEnum>(this string value, bool ignoreCase = true) where TEnum : struct, IConvertible
        {
            foreach (var o in Enum.GetValues(typeof(TEnum)))
            {
                var enumValue = (TEnum)o;
                if (ToEnumMemberValue(enumValue).Equals(value, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                    return enumValue;
            }

            throw new ArgumentException("No EnumMemberAttribute code exists for type " + typeof(TEnum).ToString() + " corresponding to value of " + value);
        }

        /// <summary>
        /// Gets the EnumMemberAttribute's value from the enum's value.
        /// </summary>
        /// <typeparam name="TEnum">The type of enum.</typeparam>
        /// <param name="value">The enum's value.</param>
        /// <returns>string.</returns>
        public static string ToEnumMemberValue<TEnum>(this TEnum value) where TEnum : struct, IConvertible
        {
            return typeof(TEnum)
                .GetTypeInfo()
                .DeclaredMembers
                .SingleOrDefault(x => x.Name == value.ToString())
                ?.GetCustomAttribute<EnumMemberAttribute>(false)
                ?.Value;
        }
    }
}
