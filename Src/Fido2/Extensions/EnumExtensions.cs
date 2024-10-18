using System;
using System.Diagnostics.CodeAnalysis;

namespace Fido2NetLib;

public static class EnumExtensions
{
    /// <summary>
    /// Gets the enum value from EnumMemberAttribute's value.
    /// </summary>
    /// <typeparam name="TEnum">The type of enum.</typeparam>
    /// <param name="value">The EnumMemberAttribute's value.</param>
    /// <returns>TEnum.</returns>
    /// <exception cref="ArgumentException">No XmlEnumAttribute code exists for type " + typeof(TEnum).ToString() + " corresponding to value of " + value</exception>
    public static TEnum ToEnum<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] TEnum>(this string value) where TEnum : struct, Enum
    {
        // Try with value from EnumMemberAttribute
        if (EnumNameMapper<TEnum>.TryGetValue(value, out var result))
        {
            return result;
        }

        // Then check the enum
        if (Enum.TryParse(value, out result))
            return result;

        throw new ArgumentException($"Value '{value}' is not a valid enum name of '{typeof(TEnum)}'. Valid values are: {string.Join(", ", EnumNameMapper<TEnum>.GetNames())}.");
    }

    /// <summary>
    /// Gets the EnumMemberAttribute's value from the enum's value.
    /// </summary>
    /// <typeparam name="TEnum">The type of enum.</typeparam>
    /// <param name="value">The enum's value</param>
    /// <returns>string.</returns>
    public static string ToEnumMemberValue<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] TEnum>(this TEnum value) where TEnum : struct, Enum
    {
        return EnumNameMapper<TEnum>.GetName(value);
    }

}
