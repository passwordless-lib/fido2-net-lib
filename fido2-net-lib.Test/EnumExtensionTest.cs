using System;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Xunit;


namespace fido2_net_lib.Test
{
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
        [InlineData("indirect", false, true)]
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
    }
}
