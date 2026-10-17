if (!navigator.credentials) {
  alert("your browser doesn't support passkeys");
  throw new Error();
}

// 1. Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying
// Party's needs for the ceremony.
const http_resp = await fetch("/pk/get-creation-options");
if (!http_resp.ok) {
  alert(`http error: ${http_resp.status}`);
  throw new Error();
}
console.log(http_resp);

const options = await http_resp.json();
console.log(options);

options.challenge = new Uint8Array(options.challenge);
options.user.id = new Uint8Array(options.user.id);

// 2. Call navigator.credentials.create() and pass options as the publicKey option. Let credential
// be the result of the successfully resolved promise. If the promise is rejected, abort the
// ceremony with a user-visible error, or otherwise guide the user experience as might be
// determinable from the context available in the rejected promise. For example if the promise is
// rejected with an error code equivalent to "InvalidStateError", the user might be instructed to
// use a different authenticator. For information on different error contexts and the circumstances
// leading to them, see §6.3.2 The authenticatorMakeCredential Operation.
let credential;
try {
  credential = await navigator.credentials.create({ publicKey: options });
  console.log(credential);
} catch (error) {
  alert(`create() error: ${error}`);
  throw new Error();
}

// 3. Let response be credential.response. If response is not an instance of
// AuthenticatorAttestationResponse, abort the ceremony with a user-visible error.
const response = credential.response;
if ((!response) instanceof AuthenticatorAttestationResponse) {
  alert("response had wrong type");
  throw new Error();
}

const body = JSON.stringify({
  clientDataJson: [...new Uint8Array(response.clientDataJSON)],
  attestationObject: [...new Uint8Array(response.attestationObject)],
});
console.log(body);
let result = await fetch("/pk/register", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: body,
});
if (!result.ok) {
  alert(`registering failed: ${await result.text()}`);
  throw new Error(result);
} else {
  alert("registered!");
}
