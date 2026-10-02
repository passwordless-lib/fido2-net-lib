#nullable enable

using Fido2NetLib;
using Fido2NetLib.Development;

using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Fido2Demo.Pages;

public class dashboardModel : PageModel
{
    private readonly IMetadataService _metadataService;

    public dashboardModel(IMetadataService metadataService)
    {
        _metadataService = metadataService;
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
            views.Add(new CredentialView(credential, await DescribeAuthenticatorAsync(credential.AaGuid)));
        }

        Credentials = views;
    }

    /// <summary>
    /// Looks the authenticator model up in the FIDO Metadata Service. Returns null when there is no metadata
    /// for the AAGUID, which is the normal case for a self-attested or "none" attestation registration.
    /// </summary>
    private async Task<string?> DescribeAuthenticatorAsync(Guid aaguid)
    {
        if (aaguid == Guid.Empty)
            return null;

        try
        {
            var entry = await _metadataService.GetEntryAsync(aaguid);
            return entry?.MetadataStatement?.Description;
        }
        catch
        {
            // The metadata service is best-effort here; the dashboard still renders without it.
            return null;
        }
    }

    public sealed class CredentialView
    {
        public CredentialView(StoredCredential credential, string? authenticatorDescription)
        {
            Credential = credential;
            AuthenticatorDescription = authenticatorDescription;
        }

        public StoredCredential Credential { get; }

        public string? AuthenticatorDescription { get; }

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
