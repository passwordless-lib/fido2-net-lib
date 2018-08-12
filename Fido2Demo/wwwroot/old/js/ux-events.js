/* eslint-env jquery */
/* global WebAuthnApp, CreateOptions, CredentialAttestation, GetOptions, CredentialAssertion */

"use strict";

(function() {
    var webAuthnConfig = {
        timeout: 30000
        // appName
    };

    function getUsernameFromEvent(event) {
        var usernameInput = $(event.target).children("input[name=username]");

        var msg = null;
        if (!usernameInput[0]) {
            msg = "internal error finding username";
        }

        var username = usernameInput[0].value;
        if (typeof username !== "string" ||
            username.length < 1) {
            msg = "Please enter a username";
        }

        if (msg) {
            throw new Error("username not set");
        }

        return username;
    }

    $("#register-form").submit(function(event) {
        event.preventDefault();
        // console.log("Register form submit.");

        // get username
        webAuthnConfig.username = getUsernameFromEvent(event);

        new WebAuthnApp(webAuthnConfig)
            .register()
            .then(function(resp) {
                // console.log("Registration complete:", resp);
            });
    });

    $("#login-form").submit(function(event) {
        event.preventDefault();
        // console.log("Login form submit.");
        // get username
        webAuthnConfig.username = getUsernameFromEvent(event);

        new WebAuthnApp(webAuthnConfig)
            .login()
            .then(function(resp) {
                // console.log("Login complete:", resp);
            });
    });

    // warn the user and disable forms if webauthn isn't supported
    $(document).on("webauthn-not-supported", function(e) {
        debugMsg("error", "WebAuthn Not Supported: " + e.detail);
        // console.log("caught webauthn not supported:", e);
        // console.log("event detail", e.detail);
        $("#notSupportedModal").modal("show");
        // change modal body to the message received from the event
        $("#notSupportedBody").html(e.detail);
        // disable "Register" and "Login" buttons
        $("#registerButton").prop("disabled", true);
        $("#loginButton").prop("disabled", true);
    });

    // show modal when user presence starts
    // this prompts users to "touch their button now" in case it isn't obvious
    // in the future, browsers may pop up their own dialoge and this will be unnecessary
    $(document).on("webauthn-user-presence-start", function() {
        debugMsg("status", "Waiting for user presence...");
        $("#upModal").modal("show");
    });

    // hide modal when user presence ends
    $(document).on("webauthn-user-presence-done", function() {
        debugMsg("status", "User presence done.");
        $("#upModal").modal("hide");
    });

    // on success or error, show a modal dialog
    // this could also be something like redirecting to a profile page on success
    $(document).on("webauthn-register-success", completeListener.bind(null, "Registration", true));
    $(document).on("webauthn-register-error", completeListener.bind(null, "Registration", false));
    $(document).on("webauthn-login-success", completeListener.bind(null, "Login", true));
    $(document).on("webauthn-login-error", completeListener.bind(null, "Login", false));

    // this shows the result modal for both login and register
    // with the message "success" when it was successful,
    // and "failure" with an error message when it failed
    function completeListener(type, success, e) {
        // hide the user presence modal, just in case it is showing
        $("#upModal").modal("hide");

        // set the details of the completion modal
        $("#resultHeader").text(`${type} Complete`);

        var body;
        console.log(e);
        var result = e.detail;
        if (success) {
            debugMsg("status", `${type} success.`);
            body = `<h3 class="alert-success">Success!</h3>`;
            if (type === "Registration") {
                body += `<p>You are now registered</p>`;
            } else {
                body += `<p>You are now logged in!`;
            }
        } else {
            debugMsg("error", `${type} error: ${result}`);
            body = `<h3 class="alert-danger">Failed!</h3>`;
            body += `<p>${result}</p>`; // error message
        }
        $("#resultBody").html(body);
        $("#resultModal").modal("show");
    }

    // be nice to users by selecting the username input on load and when tabs change
    $(document).ready(function() {
        new WebAuthnApp(); // this will fire events if there's a "not-supported" problem

        $("#register-form#username").focus();
        $("a[data-toggle=\"tab\"]").on("shown.bs.tab", function(e) {
            $("input[name=username]", $(e.target).attr("data-target")).focus();
        });

        setupDebugTerminal();
    });

    /*******************************************
    * Debugging Stuff
    *******************************************/
    function setupDebugTerminal() {
        debugMsg("status", "WebAuthn Debug Terminal");
        debugMsg("status", "-----------------------");
    }

    // log debug messages
    $(document).on("webauthn-debug", function(e) {
        var subtype = e.detail.subtype;
        var data = e.detail.data;
        switch (subtype) {
            /**** SERVER COMM EVENTS ****/
            case "send":
                break;
            case "send-raw":
                return debugPkt(true, data);
            case "response-raw":
                return debugPkt(false, data.body, data.status);
            case "response":
                var respObj = data.body;
                // options aren't interesting, only log the final result
                if (!(respObj instanceof CreateOptions) &&
                    !(respObj instanceof GetOptions)) {
                    debugMsg("result", respObj.toHumanString());
                }
                break;
            case "send-error":
                return debugMsg("error", data);

            /**** CREATE EVENTS ****/
            case "create-options":
                data = data.publicKey;
                debugMsg("webauthn", "WebAuthn navigator.credentials.create() options:\n");
                return debugMsg("webauthn", CreateOptions.toHumanString(data));
            case "create-result":
                debugMsg("webauthn", "WebAuthn navigator.credentials.create() result:\n");
                return debugMsg("webauthn", CredentialAttestation.toHumanString(data));
            case "create-error":
                return debugMsg("error", data);

            /**** GET EVENTS ****/
            case "get-options":
                data = data.publicKey;
                debugMsg("webauthn", "WebAuthn navigator.credentials.get() options:\n");
                return debugMsg("webauthn", GetOptions.toHumanString(data));
            case "get-result":
                debugMsg("webauthn", "WebAuthn navigator.credentials.get() result:\n");
                return debugMsg("webauthn", CredentialAssertion.toHumanString(data));
            case "get-error":
                return debugMsg("error", data);

            /**** DEFAULT ****/
            default:
                debugMsg("error", "INTERNAL ERROR: Unknown debug subtype: " + subtype);
        }
    });

    $(document).on("webauthn-register-start", function() {
        debugMsg("status", "Register start:");
    });

    $(document).on("webauthn-register-done", function() {
        debugMsg("status", "Register done.\n\n");
    });

    $(document).on("webauthn-login-start", function() {
        debugMsg("status", "Login start:");
    });

    $(document).on("webauthn-login-done", function() {
        debugMsg("status", "Login done.\n\n");
    });

    function debugPkt(send, body, status) {
        // body = body.match(/.{1,80}/g).join("\n");
        var msg;
        if (send) {
            msg = "\nSending Message to Server:\n";
            msg += ">>>>>>>>>>>>>>>>\n" + body + "\n>>>>>>>>>>>>>>>>\n\n";
        } else {
            msg = "Received Message from Server:\n";
            msg += `<<<<<<<< [ STATUS ${status} ] <<<<<<<<\n` + body + "\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n";

        }
        debugMsg("message", msg);
    }

    function debugMsg(cls, ...msg) {
        // consolodate msg down to a single string
        var str = "";
        msg.forEach((chunk) => {
            str += chunk;
        });
        str = str.replace(/ /g, "&nbsp;").replace(/\n/g, "<br>");

        // console.log("WebAuthn Debug:", ...msg);
        // append to console window
        writeText(str, cls);
    }

    function writeText(str, cls) {
        if (cls) str = `<div class="${cls}">${str}</div>`;
        else str = `<div>${str}</div>`;
        // console.log("Writing Text:", str);
        $(str).appendTo("#terminal");

        // scroll to bottom of terminal
        $("#terminal").scrollTop($("#terminal")[0].scrollHeight);
    }
}());
