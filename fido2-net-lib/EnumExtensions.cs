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
        public static TEnum ToEnum<TEnum>(this string value, bool ignoreCase = true) where TEnum : struct, Enum
        {
            if (Enum.TryParse<TEnum>(value, ignoreCase, out var enumValue))
            {
                return enumValue;
            }
            else 
            {
                throw new ArgumentException($"Value '{value}' is not a valid enum name of '{typeof(TEnum)}' ({nameof(ignoreCase)}={ignoreCase}). Valid values are {string.Join(";", Enum.GetNames(typeof(TEnum)))}.");
            }
        }

        /// <summary>
        /// Gets the EnumMemberAttribute's value from the enum's value.
        /// </summary>
        /// <typeparam name="TEnum">The type of enum.</typeparam>
        /// <param name="value">The enum's value.</param>
        /// <returns>string.</returns>
        public static string ToEnumMemberValue<TEnum>(this TEnum value) where TEnum : struct, Enum
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
