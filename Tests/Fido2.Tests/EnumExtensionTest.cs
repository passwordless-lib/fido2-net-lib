using Fido2NetLib.Objects;

namespace Fido2NetLib.Test;

public class EnumExtensionTest
{
    [Fact]
    public void TestToEnum()
    {
        foreach (var enumName in Enum.GetNames(typeof(AttestationConveyancePreference)))
        {
            enumName.ToEnum<AttestationConveyancePreference>();
        }
    }

    [Theory]
    // valid
    [InlineData("INDIRECT", false)]
    [InlineData("indIrEcT", false)]
    [InlineData("indirect", false)]
    [InlineData(nameof(AttestationConveyancePreference.Indirect), false)]
    // invalid
    [InlineData("Indirect_Invalid", true)]
    public void TestToEnumWithIgnoringCase(string value, bool shouldThrow)
    {
        var exception = Record.Exception(() => value.ToEnum<AttestationConveyancePreference>());

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
    // valid
    [InlineData("CROSS-PLATFORM", false)]
    [InlineData("cRoss-PlatfoRm", false)]
    [InlineData("cross-platform", false)]
    // invalid
    [InlineData("cross_platform", true)]
    [InlineData("cross-platforms", true)]
    [InlineData("CROSS_PLATFORM", true)]
    public void TestToEnumWithDashes(string value, bool shouldThrow)
    {
        var exception = Record.Exception(() => value.ToEnum<AuthenticatorAttachment>());

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
