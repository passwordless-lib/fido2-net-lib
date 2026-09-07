using System.Collections.Concurrent;

using Fido2NetLib.Objects;

namespace Fido2NetLib.Development;

public class DevelopmentInMemoryStore
{
    private readonly ConcurrentDictionary<string, Fido2User> _storedUsers = new();
    private readonly List<StoredCredential> _storedCredentials = new();

    public Fido2User GetOrAddUser(string username, Func<Fido2User> addCallback)
    {
        return _storedUsers.GetOrAdd(username, addCallback());
    }

    public Fido2User? GetUser(string username)
    {
        _storedUsers.TryGetValue(username, out var user);
        return user;
    }

    public List<StoredCredential> GetCredentialsByUser(Fido2User user)
    {
        return _storedCredentials.Where(c => c.UserId.AsSpan().SequenceEqual(user.Id)).ToList();
    }

    public StoredCredential? GetCredentialById(byte[] id)
    {
        return _storedCredentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(id));
    }

    public Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_storedCredentials.Where(c => c.UserHandle.AsSpan().SequenceEqual(userHandle)).ToList());
    }

    public void UpdateCounter(byte[] credentialId, uint counter)
    {
        var cred = _storedCredentials.First(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));
        cred.SignCount = counter;
    }

    /// <summary>
    /// Applies the credential record state updates a Relying Party performs after a successful authentication
    /// ceremony: the signature counter, the backup state, and <c>uvInitialized</c>.
    /// See step 24 of <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion"/>.
    /// </summary>
    /// <remarks>
    /// Promoting <c>uvInitialized</c> from <see langword="false"/> to <see langword="true"/> SHOULD require
    /// authorization by an additional authentication factor equivalent to WebAuthn user verification. This
    /// in-memory development store performs the update unconditionally; a real Relying Party should not.
    /// </remarks>
    public void UpdateCredentialRecord(VerifyAssertionResult assertionResult)
    {
        var cred = _storedCredentials.First(c => c.Descriptor.Id.AsSpan().SequenceEqual(assertionResult.CredentialId));

        cred.SignCount = assertionResult.SignCount;
        cred.IsBackedUp = assertionResult.IsBackedUp;

        if (!cred.UvInitialized)
            cred.UvInitialized = assertionResult.IsUserVerified;
    }

    public void AddCredentialToUser(Fido2User user, StoredCredential credential)
    {
        credential.UserId = user.Id;
        _storedCredentials.Add(credential);
    }

    /// <summary>
    /// Removes a credential. Returns <see langword="true"/> if one was found and removed.
    /// </summary>
    /// <remarks>
    /// A Relying Party that deletes a credential should also tell the authenticator, so a passkey provider
    /// stops offering an entry that will no longer be accepted: see
    /// <see cref="Objects.AllAcceptedCredentialsOptions"/> and <see cref="Objects.UnknownCredentialOptions"/>.
    /// </remarks>
    public bool RemoveCredential(byte[] credentialId)
    {
        var cred = _storedCredentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));

        if (cred is null)
            return false;

        return _storedCredentials.Remove(cred);
    }

    public Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        // our in-mem storage does not allow storing multiple users for a given credentialId. Yours shouldn't either.
        var cred = _storedCredentials.FirstOrDefault(c => c.Descriptor.Id.AsSpan().SequenceEqual(credentialId));

        if (cred is null)
            return Task.FromResult<List<Fido2User>>([]);

        return Task.FromResult(_storedUsers.Where(u => u.Value.Id.SequenceEqual(cred.UserId)).Select(u => u.Value).ToList());
    }
}
