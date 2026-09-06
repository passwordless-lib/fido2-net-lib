// Usernameless: the credential must be discoverable, because at sign-in there is no username to look
// it up by -- the authenticator produces both the credential and the user handle.

document.getElementById('register').addEventListener('submit', function (event) {
    event.preventDefault();

    registerCeremony({
        // No username field on this form; the server generates a placeholder account name.
        username: '',
        displayName: this.displayName.value,
        attestation: 'none',
        authenticatorAttachment: '',
        userVerification: 'preferred',

        // Required, not preferred: a server-side credential cannot be found without a username.
        residentKey: 'required'
    });
});
