#nullable enable

using Fido2NetLib;
using Fido2NetLib.Development;

using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Fido2Demo.Pages;

public class dashboardModel : PageModel
{
    private readonly IMetadataService _metadataService;
    private readonly IAuthenticatorDisplayMetadataService _displayMetadata;

    public dashboardModel(IMetadataService metadataService, IAuthenticatorDisplayMetadataService displayMetadata)
    {
        _metadataService = metadataService;
        _displayMetadata = displayMetadata;
    }

    public string Username { get; private set; } = "";

    /// <summary>Whether the username in the route matches a registered user.</summary>
    public bool UserExists { get; private set; }

    public IReadOnlyList<CredentialView> Credentials { get; private set; } = [];

    public async Task OnGetAsync(string username)
    {
        Username = username;

        // GetCredentialsByUser dereferences the user, so an unknown username has to be handled here rather
        // than passed through: previously this threw a NullReferenceException as soon as any credential was
        // registered, because the predicate ran against a null user.
        var user = DemoController.DemoStorage.GetUser(username);
        if (user is null)
            return;

        UserExists = true;

        var views = new List<CredentialView>();

        foreach (var credential in DemoController.DemoStorage.GetCredentialsByUser(user))
        {
            var (description, icon) = await DescribeAuthenticatorAsync(credential.AaGuid);
            views.Add(new CredentialView(credential, description, icon));
        }

        Credentials = views;
    }

    /// <summary>
    /// Names the authenticator model: from its FIDO Metadata Service statement when it has one, otherwise from
    /// the display-only metadata (which covers passkey providers such as Google Password Manager and iCloud
    /// Keychain that have no MDS statement). Both are best-effort; the dashboard renders without them.
    /// </summary>
    private async Task<(string? Description, string? Icon)> DescribeAuthenticatorAsync(Guid aaguid)
    {
        if (aaguid == Guid.Empty)
            return (null, null);

        string? description = null;

        try
        {
            var entry = await _metadataService.GetEntryAsync(aaguid);
            description = entry?.MetadataStatement?.Description;
        }
        catch
        {
            // The metadata service is best-effort here.
        }

        // Display metadata never throws for a failed download; it just has nothing to say.
        var display = await _displayMetadata.GetDisplayInfoAsync(aaguid);

        return (description ?? display?.Name, display?.IconLight);
    }

    public sealed class CredentialView
    {
        public CredentialView(StoredCredential credential, string? authenticatorDescription, string? authenticatorIcon)
        {
            Credential = credential;
            AuthenticatorDescription = authenticatorDescription;
            AuthenticatorIcon = authenticatorIcon;
        }

        public StoredCredential Credential { get; }

        public string? AuthenticatorDescription { get; }

        /// <summary>A <c>data:image/...</c> URL, only ever rendered as an <c>img</c> source.</summary>
        public string? AuthenticatorIcon { get; }

        public string CredentialId => Convert.ToBase64String(Credential.Id);

        public string PublicKey => Convert.ToBase64String(Credential.PublicKey);

        /// <summary>
        /// A user handle is an opaque byte sequence, not text -- the spec explicitly says it "MUST NOT contain
        /// personally identifying information". The demo happens to use UTF-8 usernames, so show that when it
        /// decodes and fall back to base64 when it does not.
        /// </summary>
        public string UserHandle => Describe(Credential.UserHandle);

        public string UserId => Describe(Credential.UserId);

        private static string Describe(byte[]? value)
        {
            if (value is null || value.Length == 0)
                return "";

            try
            {
                return new System.Text.UTF8Encoding(false, throwOnInvalidBytes: true).GetString(value);
            }
            catch (ArgumentException)
            {
                return Convert.ToBase64String(value);
            }
        }
    }
}
