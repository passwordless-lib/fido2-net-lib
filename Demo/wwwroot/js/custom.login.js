// Custom sign-in: user verification and hints come from the option controls.

document.getElementById('signin').addEventListener('submit', function (event) {
    event.preventDefault();

    signInCeremony({
        username: this.username.value,
        userVerification: value('#option-userverification'),
        hints: checkedValues('.option-hint')
    });
});
