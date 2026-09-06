// Usernameless sign-in: no username is sent, so the server returns an empty allowCredentials list and
// the authenticator offers whichever discoverable credentials it holds for this RP ID.

document.getElementById('signin').addEventListener('submit', function (event) {
    event.preventDefault();

    signInCeremony({
        userVerification: 'preferred'
    });
});
