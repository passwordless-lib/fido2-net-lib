using System.ComponentModel.DataAnnotations;

namespace Fido2NetLib.Objects
{
    public sealed class PublicKeyCredentialUserEntity
    {
        [MaxLength(64)]
        public byte[] Id { get; set; }

        public string Name { get; set; }

        public string DisplayName { get; set; }

        public string Icon { get; set; }
    }
}
