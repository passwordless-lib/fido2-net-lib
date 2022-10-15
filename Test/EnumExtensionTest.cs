using Fido2NetLib;
using Fido2NetLib.Objects;

namespace fido2_net_lib.Test;

public class EnumExtensionTest
{
    [Fact]
    public void TestToEnum()
    {
        var enumNames = Enum.GetNames(typeof(AttestationConveyancePreference));
        foreach (var enumName in enumNames)
        {
            enumName.ToEnum<AttestationConveyancePreference>();
        }
    }

    [Theory]
    // ignoreCase true, valid
    [InlineData("INDIRECT", true, false)]
    [InlineData("indIrEcT", true, false)]
    [InlineData("indirect", true, false)]

    // invalid
    [InlineData("Indirect_Invalid", true, true)]

    // ignoreCase false, valid
    [InlineData(nameof(AttestationConveyancePreference.Indirect), false, false)]

    // invalid
    [InlineData("Indirect_Invalid", false, true)]
    [InlineData("INDIRECT", false, true)]
    [InlineData("indIrEcT", false, true)]
    public void TestToEnumWithIgnoringCase(string value, bool ignoreCase, bool shouldThrow)
    {
        var exception = Record.Exception(() => value.ToEnum<AttestationConveyancePreference>(ignoreCase));

        if (shouldThrow)
        {
            Assert.IsType<ArgumentException>(exception);
        }
        else
        {
            Assert.Null(exception);
        }
    }

    [Theory]
    [InlineData("CROSS-PLATFORM", true, false)] // valid
    [InlineData("cRoss-PlatfoRm", true, false)] // valid
    [InlineData("cross-platform", true, false)] // valid
    [InlineData("cross_platform", true, true)]  // invalid
    [InlineData("cross-platforms", true, true)] // invalid
    [InlineData("CROSS_PLATFORM", true, true)]  // invalid
    [InlineData("CROSS-PLATFORM", false, true)] // invalid
    [InlineData("cRoss-PlatfoRm", false, true)] // invalid
    public void TestToEnumWithDashes(string value, bool ignoreCase, bool shouldThrow)
    {
        var exception = Record.Exception(() => value.ToEnum<AuthenticatorAttachment>(ignoreCase));

        if (shouldThrow)
        {
            Assert.IsType<ArgumentException>(exception);
        }
        else
        {
            Assert.Null(exception);
        }
    }
}
