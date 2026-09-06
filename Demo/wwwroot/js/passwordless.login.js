// Passwordless sign-in: username identifies the account, the authenticator supplies the verification.

document.getElementById('signin').addEventListener('submit', function (event) {
    event.preventDefault();

    signInCeremony({
        username: this.username.value,
        userVerification: 'preferred',
        hints: ['client-device']
    });
});
