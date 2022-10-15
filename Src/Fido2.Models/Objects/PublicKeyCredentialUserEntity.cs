using System.ComponentModel.DataAnnotations;

namespace Fido2NetLib.Objects
{
    public sealed class PublicKeyCredentialUserEntity
    {
        [MaxLength(64)]
#pragma warning disable IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code
        public byte[] Id { get; set; }
#pragma warning restore IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code

        public string Name { get; set; }

        public string DisplayName { get; set; }

        public string Icon { get; set; }
    }
}
