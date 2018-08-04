[![Sauce Test Status](https://saucelabs.com/browser-matrix/apowers313.svg)](https://saucelabs.com/u/apowers313)

node.js: [![Build Status](https://travis-ci.org/apowers313/webauthn-simple-app.svg?branch=master)](https://travis-ci.org/apowers313/webauthn-simple-app)

This module makes passwordless (or second-factor) [W3C's](https://www.w3.org/TR/webauthn/) [Web Authentication](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) simple. The primary interface is the [WebAuthnApp](https://apowers313.github.io/webauthn-simple-app/WebAuthnApp.html) class, with the `register()` and `login()` methods for registering new devices and / or logging in via WebAuthn. The interface takes care of communicating with your WebAuthn server, validating server responses, calling the browser's WebAuthn API with the right options, and everything else.

There is much more functionality available for debugging or more granular control, but it probably isn't needed for most applications.

The module is also exported as a `npm` module, allowing the [Msg](https://apowers313.github.io/webauthn-simple-app/Msg.html) class to be used in `node.js` servers for creating, validating, and converting all the communications with a browser.

For a live demo of this project, see [webauthn.org](https://webauthn.org).

Documentation for all classes and advanced options is [available online](https://apowers313.github.io/webauthn-simple-app).

## Install

**npm**
``` js
npm install webauthn-simple-app
```

**CDN**
``` html
<!-- coming soon -->
```

**GitHub**
```
git clone https://github.com/apowers313/webauthn-simple-app
```

**Download**
Coming soon!

## Simple Example

**Register:**
``` js
// register a new device / account
var waApp = new WebAuthnApp()
waApp.username = "me";
waApp.register()
    .then(() => {
        alert("You are now registered!");
    })
    .catch((err) => {
        alert("Registration error: " + err.message);
    });
```

**Log in:**
``` js
// log in to a previously registered account
var waApp = new WebAuthnApp()
waApp.username = "me";
waApp.login()
    .then(() => {
        alert("You are now logged in!");
    })
    .catch((err) => {
        alert("Log in error: " + err.message);
    });
```

## Real Example

Here is a more complete example, using [jQuery](https://jquery.com/) to do things like get inputs from forms and respond to various events that are fired.

**JavaScript**
``` js
// override some of the default configuration options
// see the docs for a full list of configuration options
var webAuthnConfig = {
    timeout: 30000
};

// when user clicks submit in the register form, start the registration process
$("#register-form").submit(function(event) {
    event.preventDefault();
    webAuthnConfig.username = $(event.target).children("input[name=username]")[0].value
    new WebAuthnApp(webAuthnConfig).register();
});

// when user clicks submit in the login form, start the log in process
$("#login-form").submit(function(event) {
    event.preventDefault();
    webAuthnConfig.username = $(event.target).children("input[name=username]")[0].value
    new WebAuthnApp(webAuthnConfig).login();
});

// do something when registration is successful
$(document).on("webauthn-register-success", () => {
    window.location = "https://example.com/sign-in-page";
});

// do something when registration fails
$(document).on("webauthn-register-error", (err) => {
    // probably do something nice like a toast or a modal...
    alert("Registration error: " + err.message);
});

// do something when log in is successful
$(document).on("webauthn-login-success", () => {
    window.location = "https://example.com/my-profile-page";
});

// do something when log in fails
$(document).on("webauthn-login-error", (err) => {
    // probably do something nice like a toast or a modal...
    alert("Log in error: " + err.message);
});

// gently remind the user to authenticate when it's time
$(document).on("webauthn-user-presence-start", (err) => {
  // probably do something nice like a toast or a modal...
    alert("Please perform user verification on your authenticator now!");
});
```

**HTML**
``` html
<html>
    <!-- A very simple registration form -->
    <form id="register-form">
        <input type="text" id="username" name="username" placeholder="Username" autofocus="autofocus">
        <input type="submit" id="registerButton" class="btn btn-success" value="Register">
    </form>

    <!-- A very simple log in form -->
    <form id="login-form">
        <input type="text" id="username" name="username" placeholder="Username" autofocus="autofocus">
        <input type="submit" id="loginButton" class="btn btn-success" value="Login">
    </form>
</html>
```

## Complete Example
For a complete example using jQuery and Bootstrap, refer to the code at the [webauthn-yubiclone](https://github.com/apowers313/webauthn-yubiclone) project, specifically [index.html](https://github.com/apowers313/webauthn-yubiclone/blob/master/index.html) and [ux-events.js](https://github.com/apowers313/webauthn-yubiclone/blob/master/js/ux-events.js).

## Theory of Operation

Here's what's going on inside when you call `register` or `login`:

**WebAuthnApp.register():**
* getRegisterOptions()
    * client --> CreateOptionsRequest --> server
    * client <-- CreateOptions <-- server
* create()
    * CredentialAttestation = navigator.credentials.create(CreateOptions)
* sendRegisterResult()
    * client --> CredentialAttestation --> server
    * client <-- ServerResponse <-- server

**WebAuthnApp.login():**
* getLoginOptions()
    * client --> GetOptionsRequest --> server
    * client <-- GetOptions <-- server
* get()
    * CredentialAssertion = navigator.credentials.get(GetOptions)
* sendLoginResult()
    * client --> CredentialAssertion --> server
    * client <-- ServerResponse <-- server

## License: MIT
Copyright 2018 Adam Powers

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
