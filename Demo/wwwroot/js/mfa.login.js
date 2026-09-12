// Second-factor sign-in: the username is known from the first factor, so the server can send an
// allowCredentials list and the authenticator does not need to be discoverable.

document.getElementById('signin').addEventListener('submit', function (event) {
    event.preventDefault();

    signInCeremony({
        username: this.username.value,
        userVerification: 'discouraged'
    });
});
