(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[888],{2191:function(e,t,n){"use strict";n.d(t,{$:function(){return tc},A:function(){return c},B:function(){return d},G:function(){return eT},H:function(){return ek},J:function(){return eq},L:function(){return ei},M:function(){return eH},N:function(){return eJ},P:function(){return nE},Q:function(){return eZ},R:function(){return ny},T:function(){return e0},U:function(){return eX},V:function(){return e2},W:function(){return e3},X:function(){return e9},Y:function(){return ta},Z:function(){return to},_:function(){return tl},a:function(){return tJ},a0:function(){return tp},a1:function(){return tm},a2:function(){return tg},a3:function(){return ty},a4:function(){return tv},a5:function(){return tw},a6:function(){return t_},a7:function(){return tb},a8:function(){return tI},a9:function(){return tT},aA:function(){return es},aB:function(){return nX},aC:function(){return nB},aD:function(){return nq},aE:function(){return eb},aI:function(){return t0},aL:function(){return e1},aa:function(){return tS},ab:function(){return tk},ac:function(){return tA},af:function(){return tx},ag:function(){return tN},ah:function(){return tR},ak:function(){return tt},al:function(){return tV},an:function(){return tz},ao:function(){return tK},ap:function(){return T},aq:function(){return em},ar:function(){return ed},as:function(){return g},at:function(){return rs},au:function(){return n2},av:function(){return eg},aw:function(){return y},ax:function(){return b},ay:function(){return nZ},az:function(){return S},b:function(){return tY},c:function(){return nD},d:function(){return nP},e:function(){return nO},f:function(){return n$},g:function(){return nH},h:function(){return nK},i:function(){return ns},j:function(){return nY},k:function(){return ro},l:function(){return n_},m:function(){return rc},o:function(){return u},r:function(){return nb},s:function(){return nw},u:function(){return nT},v:function(){return tq}});var r,i=n(4444),s=n(5816),a=n(3333);function o(e,t){var n={};for(var r in e)Object.prototype.hasOwnProperty.call(e,r)&&0>t.indexOf(r)&&(n[r]=e[r]);if(null!=e&&"function"==typeof Object.getOwnPropertySymbols)for(var i=0,r=Object.getOwnPropertySymbols(e);i<r.length;i++)0>t.indexOf(r[i])&&Object.prototype.propertyIsEnumerable.call(e,r[i])&&(n[r[i]]=e[r[i]]);return n}var l=n(8463);let u={FACEBOOK:"facebook.com",GITHUB:"github.com",GOOGLE:"google.com",PASSWORD:"password",PHONE:"phone",TWITTER:"twitter.com"},c={EMAIL_SIGNIN:"EMAIL_SIGNIN",PASSWORD_RESET:"PASSWORD_RESET",RECOVER_EMAIL:"RECOVER_EMAIL",REVERT_SECOND_FACTOR_ADDITION:"REVERT_SECOND_FACTOR_ADDITION",VERIFY_AND_CHANGE_EMAIL:"VERIFY_AND_CHANGE_EMAIL",VERIFY_EMAIL:"VERIFY_EMAIL"};function h(){return{"dependent-sdk-initialized-before-auth":"Another Firebase SDK was initialized and is trying to use Auth before Auth is initialized. Please be sure to call `initializeAuth` or `getAuth` before starting any other Firebase SDK."}}let d=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(){return{"admin-restricted-operation":"This operation is restricted to administrators only.","argument-error":"","app-not-authorized":"This app, identified by the domain where it's hosted, is not authorized to use Firebase Authentication with the provided API key. Review your key configuration in the Google API console.","app-not-installed":"The requested mobile application corresponding to the identifier (Android package name or iOS bundle ID) provided is not installed on this device.","captcha-check-failed":"The reCAPTCHA response token provided is either invalid, expired, already used or the domain associated with it does not match the list of whitelisted domains.","code-expired":"The SMS code has expired. Please re-send the verification code to try again.","cordova-not-ready":"Cordova framework is not ready.","cors-unsupported":"This browser is not supported.","credential-already-in-use":"This credential is already associated with a different user account.","custom-token-mismatch":"The custom token corresponds to a different audience.","requires-recent-login":"This operation is sensitive and requires recent authentication. Log in again before retrying this request.","dependent-sdk-initialized-before-auth":"Another Firebase SDK was initialized and is trying to use Auth before Auth is initialized. Please be sure to call `initializeAuth` or `getAuth` before starting any other Firebase SDK.","dynamic-link-not-activated":"Please activate Dynamic Links in the Firebase Console and agree to the terms and conditions.","email-change-needs-verification":"Multi-factor users must always have a verified email.","email-already-in-use":"The email address is already in use by another account.","emulator-config-failed":'Auth instance has already been used to make a network call. Auth can no longer be configured to use the emulator. Try calling "connectAuthEmulator()" sooner.',"expired-action-code":"The action code has expired.","cancelled-popup-request":"This operation has been cancelled due to another conflicting popup being opened.","internal-error":"An internal AuthError has occurred.","invalid-app-credential":"The phone verification request contains an invalid application verifier. The reCAPTCHA token response is either invalid or expired.","invalid-app-id":"The mobile app identifier is not registed for the current project.","invalid-user-token":"This user's credential isn't valid for this project. This can happen if the user's token has been tampered with, or if the user isn't for the project associated with this API key.","invalid-auth-event":"An internal AuthError has occurred.","invalid-verification-code":"The SMS verification code used to create the phone auth credential is invalid. Please resend the verification code sms and be sure to use the verification code provided by the user.","invalid-continue-uri":"The continue URL provided in the request is invalid.","invalid-cordova-configuration":"The following Cordova plugins must be installed to enable OAuth sign-in: cordova-plugin-buildinfo, cordova-universal-links-plugin, cordova-plugin-browsertab, cordova-plugin-inappbrowser and cordova-plugin-customurlscheme.","invalid-custom-token":"The custom token format is incorrect. Please check the documentation.","invalid-dynamic-link-domain":"The provided dynamic link domain is not configured or authorized for the current project.","invalid-email":"The email address is badly formatted.","invalid-emulator-scheme":"Emulator URL must start with a valid scheme (http:// or https://).","invalid-api-key":"Your API key is invalid, please check you have copied it correctly.","invalid-cert-hash":"The SHA-1 certificate hash provided is invalid.","invalid-credential":"The supplied auth credential is malformed or has expired.","invalid-message-payload":"The email template corresponding to this action contains invalid characters in its message. Please fix by going to the Auth email templates section in the Firebase Console.","invalid-multi-factor-session":"The request does not contain a valid proof of first factor successful sign-in.","invalid-oauth-provider":"EmailAuthProvider is not supported for this operation. This operation only supports OAuth providers.","invalid-oauth-client-id":"The OAuth client ID provided is either invalid or does not match the specified API key.","unauthorized-domain":"This domain is not authorized for OAuth operations for your Firebase project. Edit the list of authorized domains from the Firebase console.","invalid-action-code":"The action code is invalid. This can happen if the code is malformed, expired, or has already been used.","wrong-password":"The password is invalid or the user does not have a password.","invalid-persistence-type":"The specified persistence type is invalid. It can only be local, session or none.","invalid-phone-number":"The format of the phone number provided is incorrect. Please enter the phone number in a format that can be parsed into E.164 format. E.164 phone numbers are written in the format [+][country code][subscriber number including area code].","invalid-provider-id":"The specified provider ID is invalid.","invalid-recipient-email":"The email corresponding to this action failed to send as the provided recipient email address is invalid.","invalid-sender":"The email template corresponding to this action contains an invalid sender email or name. Please fix by going to the Auth email templates section in the Firebase Console.","invalid-verification-id":"The verification ID used to create the phone auth credential is invalid.","invalid-tenant-id":"The Auth instance's tenant ID is invalid.","login-blocked":"Login blocked by user-provided method: {$originalMessage}","missing-android-pkg-name":"An Android Package Name must be provided if the Android App is required to be installed.","auth-domain-config-required":"Be sure to include authDomain when calling firebase.initializeApp(), by following the instructions in the Firebase console.","missing-app-credential":"The phone verification request is missing an application verifier assertion. A reCAPTCHA response token needs to be provided.","missing-verification-code":"The phone auth credential was created with an empty SMS verification code.","missing-continue-uri":"A continue URL must be provided in the request.","missing-iframe-start":"An internal AuthError has occurred.","missing-ios-bundle-id":"An iOS Bundle ID must be provided if an App Store ID is provided.","missing-or-invalid-nonce":"The request does not contain a valid nonce. This can occur if the SHA-256 hash of the provided raw nonce does not match the hashed nonce in the ID token payload.","missing-multi-factor-info":"No second factor identifier is provided.","missing-multi-factor-session":"The request is missing proof of first factor successful sign-in.","missing-phone-number":"To send verification codes, provide a phone number for the recipient.","missing-verification-id":"The phone auth credential was created with an empty verification ID.","app-deleted":"This instance of FirebaseApp has been deleted.","multi-factor-info-not-found":"The user does not have a second factor matching the identifier provided.","multi-factor-auth-required":"Proof of ownership of a second factor is required to complete sign-in.","account-exists-with-different-credential":"An account already exists with the same email address but different sign-in credentials. Sign in using a provider associated with this email address.","network-request-failed":"A network AuthError (such as timeout, interrupted connection or unreachable host) has occurred.","no-auth-event":"An internal AuthError has occurred.","no-such-provider":"User was not linked to an account with the given provider.","null-user":"A null user object was provided as the argument for an operation which requires a non-null user object.","operation-not-allowed":"The given sign-in provider is disabled for this Firebase project. Enable it in the Firebase console, under the sign-in method tab of the Auth section.","operation-not-supported-in-this-environment":'This operation is not supported in the environment this application is running on. "location.protocol" must be http, https or chrome-extension and web storage must be enabled.',"popup-blocked":"Unable to establish a connection with the popup. It may have been blocked by the browser.","popup-closed-by-user":"The popup has been closed by the user before finalizing the operation.","provider-already-linked":"User can only be linked to one identity for the given provider.","quota-exceeded":"The project's quota for this operation has been exceeded.","redirect-cancelled-by-user":"The redirect operation has been cancelled by the user before finalizing.","redirect-operation-pending":"A redirect sign-in operation is already pending.","rejected-credential":"The request contains malformed or mismatching credentials.","second-factor-already-in-use":"The second factor is already enrolled on this account.","maximum-second-factor-count-exceeded":"The maximum allowed number of second factors on a user has been exceeded.","tenant-id-mismatch":"The provided tenant ID does not match the Auth instance's tenant ID",timeout:"The operation has timed out.","user-token-expired":"The user's credential is no longer valid. The user must sign in again.","too-many-requests":"We have blocked all requests from this device due to unusual activity. Try again later.","unauthorized-continue-uri":"The domain of the continue URL is not whitelisted.  Please whitelist the domain in the Firebase console.","unsupported-first-factor":"Enrolling a second factor or signing in with a multi-factor account requires sign-in with a supported first factor.","unsupported-persistence-type":"The current environment does not support the specified persistence type.","unsupported-tenant-operation":"This operation is not supported in a multi-tenant context.","unverified-email":"The operation requires a verified email.","user-cancelled":"The user did not grant your application the permissions it requested.","user-not-found":"There is no user record corresponding to this identifier. The user may have been deleted.","user-disabled":"The user account has been disabled by an administrator.","user-mismatch":"The supplied credentials do not correspond to the previously signed in user.","user-signed-out":"","weak-password":"The password must be 6 characters long or more.","web-storage-unsupported":"This browser is not supported or 3rd party cookies and data may be disabled.","already-initialized":"initializeAuth() has already been called with different options. To avoid this error, call initializeAuth() with the same options as when it was originally called, or call getAuth() to return the already initialized instance."}},f=new i.LL("auth","Firebase",h()),p=new a.Yd("@firebase/auth");function m(e,...t){p.logLevel<=a.in.ERROR&&p.error(`Auth (${s.SDK_VERSION}): ${e}`,...t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function g(e,...t){throw _(e,...t)}function y(e,...t){return _(e,...t)}function v(e,t,n){let r=Object.assign(Object.assign({},h()),{[t]:n}),s=new i.LL("auth","Firebase",r);return s.create(t,{appName:e.name})}function w(e,t,n){if(!(t instanceof n))throw n.name!==t.constructor.name&&g(e,"argument-error"),v(e,"argument-error",`Type of ${t.constructor.name} does not match expected instance.Did you pass a reference from a different Auth SDK?`)}function _(e,...t){if("string"!=typeof e){let n=t[0],r=[...t.slice(1)];return r[0]&&(r[0].appName=e.name),e._errorFactory.create(n,...r)}return f.create(e,...t)}function b(e,t,...n){if(!e)throw _(t,...n)}function I(e){let t="INTERNAL ASSERTION FAILED: "+e;throw m(t),Error(t)}function T(e,t){e||I(t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let E=new Map;function S(e){T(e instanceof Function,"Expected a class definition");let t=E.get(e);return t?(T(t instanceof e,"Instance stored in cache mismatched with class"),t):(t=new e,E.set(e,t),t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function k(){var e;return"undefined"!=typeof self&&(null===(e=self.location)||void 0===e?void 0:e.href)||""}function A(){return"http:"===C()||"https:"===C()}function C(){var e;return"undefined"!=typeof self&&(null===(e=self.location)||void 0===e?void 0:e.protocol)||null}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class x{constructor(e,t){this.shortDelay=e,this.longDelay=t,T(t>e,"Short delay should be less than long delay!"),this.isMobile=(0,i.uI)()||(0,i.b$)()}get(){return!("undefined"!=typeof navigator&&navigator&&"onLine"in navigator&&"boolean"==typeof navigator.onLine&&(A()||(0,i.ru)()||"connection"in navigator))||navigator.onLine?this.isMobile?this.longDelay:this.shortDelay:Math.min(5e3,this.shortDelay)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function N(e,t){T(e.emulator,"Emulator should always be set here");let{url:n}=e.emulator;return t?`${n}${t.startsWith("/")?t.slice(1):t}`:n}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class R{static initialize(e,t,n){this.fetchImpl=e,t&&(this.headersImpl=t),n&&(this.responseImpl=n)}static fetch(){return this.fetchImpl?this.fetchImpl:"undefined"!=typeof self&&"fetch"in self?self.fetch:void I("Could not find fetch implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}static headers(){return this.headersImpl?this.headersImpl:"undefined"!=typeof self&&"Headers"in self?self.Headers:void I("Could not find Headers implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}static response(){return this.responseImpl?this.responseImpl:"undefined"!=typeof self&&"Response"in self?self.Response:void I("Could not find Response implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let D={CREDENTIAL_MISMATCH:"custom-token-mismatch",MISSING_CUSTOM_TOKEN:"internal-error",INVALID_IDENTIFIER:"invalid-email",MISSING_CONTINUE_URI:"internal-error",INVALID_PASSWORD:"wrong-password",MISSING_PASSWORD:"internal-error",EMAIL_EXISTS:"email-already-in-use",PASSWORD_LOGIN_DISABLED:"operation-not-allowed",INVALID_IDP_RESPONSE:"invalid-credential",INVALID_PENDING_TOKEN:"invalid-credential",FEDERATED_USER_ID_ALREADY_LINKED:"credential-already-in-use",MISSING_REQ_TYPE:"internal-error",EMAIL_NOT_FOUND:"user-not-found",RESET_PASSWORD_EXCEED_LIMIT:"too-many-requests",EXPIRED_OOB_CODE:"expired-action-code",INVALID_OOB_CODE:"invalid-action-code",MISSING_OOB_CODE:"internal-error",CREDENTIAL_TOO_OLD_LOGIN_AGAIN:"requires-recent-login",INVALID_ID_TOKEN:"invalid-user-token",TOKEN_EXPIRED:"user-token-expired",USER_NOT_FOUND:"user-token-expired",TOO_MANY_ATTEMPTS_TRY_LATER:"too-many-requests",INVALID_CODE:"invalid-verification-code",INVALID_SESSION_INFO:"invalid-verification-id",INVALID_TEMPORARY_PROOF:"invalid-credential",MISSING_SESSION_INFO:"missing-verification-id",SESSION_EXPIRED:"code-expired",MISSING_ANDROID_PACKAGE_NAME:"missing-android-pkg-name",UNAUTHORIZED_DOMAIN:"unauthorized-continue-uri",INVALID_OAUTH_CLIENT_ID:"invalid-oauth-client-id",ADMIN_ONLY_OPERATION:"admin-restricted-operation",INVALID_MFA_PENDING_CREDENTIAL:"invalid-multi-factor-session",MFA_ENROLLMENT_NOT_FOUND:"multi-factor-info-not-found",MISSING_MFA_ENROLLMENT_ID:"missing-multi-factor-info",MISSING_MFA_PENDING_CREDENTIAL:"missing-multi-factor-session",SECOND_FACTOR_EXISTS:"second-factor-already-in-use",SECOND_FACTOR_LIMIT_EXCEEDED:"maximum-second-factor-count-exceeded",BLOCKING_FUNCTION_ERROR_RESPONSE:"internal-error"},O=new x(3e4,6e4);function P(e,t){return e.tenantId&&!t.tenantId?Object.assign(Object.assign({},t),{tenantId:e.tenantId}):t}async function L(e,t,n,r,s={}){return M(e,s,async()=>{let s={},a={};r&&("GET"===t?a=r:s={body:JSON.stringify(r)});let o=(0,i.xO)(Object.assign({key:e.config.apiKey},a)).slice(1),l=await e._getAdditionalHeaders();return l["Content-Type"]="application/json",e.languageCode&&(l["X-Firebase-Locale"]=e.languageCode),R.fetch()(F(e,e.config.apiHost,n,o),Object.assign({method:t,headers:l,referrerPolicy:"no-referrer"},s))})}async function M(e,t,n){e._canInitEmulator=!1;let r=Object.assign(Object.assign({},D),t);try{let t=new V(e),i=await Promise.race([n(),t.promise]);t.clearNetworkTimeout();let s=await i.json();if("needConfirmation"in s)throw q(e,"account-exists-with-different-credential",s);if(i.ok&&!("errorMessage"in s))return s;{let t=i.ok?s.errorMessage:s.error.message,[n,a]=t.split(" : ");if("FEDERATED_USER_ID_ALREADY_LINKED"===n)throw q(e,"credential-already-in-use",s);if("EMAIL_EXISTS"===n)throw q(e,"email-already-in-use",s);if("USER_DISABLED"===n)throw q(e,"user-disabled",s);let o=r[n]||n.toLowerCase().replace(/[_\s]+/g,"-");if(a)throw v(e,o,a);g(e,o)}}catch(t){if(t instanceof i.ZR)throw t;g(e,"network-request-failed")}}async function U(e,t,n,r,i={}){let s=await L(e,t,n,r,i);return"mfaPendingCredential"in s&&g(e,"multi-factor-auth-required",{_serverResponse:s}),s}function F(e,t,n,r){let i=`${t}${n}?${r}`;return e.config.emulator?N(e.config,i):`${e.config.apiScheme}://${i}`}class V{constructor(e){this.auth=e,this.timer=null,this.promise=new Promise((e,t)=>{this.timer=setTimeout(()=>t(y(this.auth,"network-request-failed")),O.get())})}clearNetworkTimeout(){clearTimeout(this.timer)}}function q(e,t,n){let r={appName:e.name};n.email&&(r.email=n.email),n.phoneNumber&&(r.phoneNumber=n.phoneNumber);let i=y(e,t,r);return i.customData._tokenResponse=n,i}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function B(e,t){return L(e,"POST","/v1/accounts:delete",t)}async function j(e,t){return L(e,"POST","/v1/accounts:update",t)}async function z(e,t){return L(e,"POST","/v1/accounts:lookup",t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function $(e){if(e)try{let t=new Date(Number(e));if(!isNaN(t.getTime()))return t.toUTCString()}catch(e){}}async function G(e,t=!1){let n=(0,i.m9)(e),r=await n.getIdToken(t),s=W(r);b(s&&s.exp&&s.auth_time&&s.iat,n.auth,"internal-error");let a="object"==typeof s.firebase?s.firebase:void 0,o=null==a?void 0:a.sign_in_provider;return{claims:s,token:r,authTime:$(K(s.auth_time)),issuedAtTime:$(K(s.iat)),expirationTime:$(K(s.exp)),signInProvider:o||null,signInSecondFactor:(null==a?void 0:a.sign_in_second_factor)||null}}function K(e){return 1e3*Number(e)}function W(e){let[t,n,r]=e.split(".");if(void 0===t||void 0===n||void 0===r)return m("JWT malformed, contained fewer than 3 sections"),null;try{let e=(0,i.tV)(n);if(!e)return m("Failed to decode base64 JWT payload"),null;return JSON.parse(e)}catch(e){return m("Caught error parsing JWT payload as JSON",null==e?void 0:e.toString()),null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function H(e,t,n=!1){if(n)return t;try{return await t}catch(t){throw t instanceof i.ZR&&function({code:e}){return"auth/user-disabled"===e||"auth/user-token-expired"===e}(t)&&e.auth.currentUser===e&&await e.auth.signOut(),t}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class Q{constructor(e){this.user=e,this.isRunning=!1,this.timerId=null,this.errorBackoff=3e4}_start(){this.isRunning||(this.isRunning=!0,this.schedule())}_stop(){this.isRunning&&(this.isRunning=!1,null!==this.timerId&&clearTimeout(this.timerId))}getInterval(e){var t;if(e){let e=this.errorBackoff;return this.errorBackoff=Math.min(2*this.errorBackoff,96e4),e}{this.errorBackoff=3e4;let e=null!==(t=this.user.stsTokenManager.expirationTime)&&void 0!==t?t:0,n=e-Date.now()-3e5;return Math.max(0,n)}}schedule(e=!1){if(!this.isRunning)return;let t=this.getInterval(e);this.timerId=setTimeout(async()=>{await this.iteration()},t)}async iteration(){try{await this.user.getIdToken(!0)}catch(e){(null==e?void 0:e.code)==="auth/network-request-failed"&&this.schedule(!0);return}this.schedule()}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class Y{constructor(e,t){this.createdAt=e,this.lastLoginAt=t,this._initializeTime()}_initializeTime(){this.lastSignInTime=$(this.lastLoginAt),this.creationTime=$(this.createdAt)}_copy(e){this.createdAt=e.createdAt,this.lastLoginAt=e.lastLoginAt,this._initializeTime()}toJSON(){return{createdAt:this.createdAt,lastLoginAt:this.lastLoginAt}}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function X(e){var t;let n=e.auth,r=await e.getIdToken(),i=await H(e,z(n,{idToken:r}));b(null==i?void 0:i.users.length,n,"internal-error");let s=i.users[0];e._notifyReloadListener(s);let a=(null===(t=s.providerUserInfo)||void 0===t?void 0:t.length)?s.providerUserInfo.map(e=>{var{providerId:t}=e,n=o(e,["providerId"]);return{providerId:t,uid:n.rawId||"",displayName:n.displayName||null,email:n.email||null,phoneNumber:n.phoneNumber||null,photoURL:n.photoUrl||null}}):[],l=function(e,t){let n=e.filter(e=>!t.some(t=>t.providerId===e.providerId));return[...n,...t]}(e.providerData,a),u=e.isAnonymous,c=!(e.email&&s.passwordHash)&&!(null==l?void 0:l.length),h={uid:s.localId,displayName:s.displayName||null,photoURL:s.photoUrl||null,email:s.email||null,emailVerified:s.emailVerified||!1,phoneNumber:s.phoneNumber||null,tenantId:s.tenantId||null,providerData:l,metadata:new Y(s.createdAt,s.lastLoginAt),isAnonymous:!!u&&c};Object.assign(e,h)}async function J(e){let t=(0,i.m9)(e);await X(t),await t.auth._persistUserIfCurrent(t),t.auth._notifyListenersIfCurrent(t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function Z(e,t){let n=await M(e,{},async()=>{let n=(0,i.xO)({grant_type:"refresh_token",refresh_token:t}).slice(1),{tokenApiHost:r,apiKey:s}=e.config,a=F(e,r,"/v1/token",`key=${s}`),o=await e._getAdditionalHeaders();return o["Content-Type"]="application/x-www-form-urlencoded",R.fetch()(a,{method:"POST",headers:o,body:n})});return{accessToken:n.access_token,expiresIn:n.expires_in,refreshToken:n.refresh_token}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ee{constructor(){this.refreshToken=null,this.accessToken=null,this.expirationTime=null}get isExpired(){return!this.expirationTime||Date.now()>this.expirationTime-3e4}updateFromServerResponse(e){b(e.idToken,"internal-error"),b(void 0!==e.idToken,"internal-error"),b(void 0!==e.refreshToken,"internal-error");let t="expiresIn"in e&&void 0!==e.expiresIn?Number(e.expiresIn):function(e){let t=W(e);return b(t,"internal-error"),b(void 0!==t.exp,"internal-error"),b(void 0!==t.iat,"internal-error"),Number(t.exp)-Number(t.iat)}(e.idToken);this.updateTokensAndExpiration(e.idToken,e.refreshToken,t)}async getToken(e,t=!1){return(b(!this.accessToken||this.refreshToken,e,"user-token-expired"),t||!this.accessToken||this.isExpired)?this.refreshToken?(await this.refresh(e,this.refreshToken),this.accessToken):null:this.accessToken}clearRefreshToken(){this.refreshToken=null}async refresh(e,t){let{accessToken:n,refreshToken:r,expiresIn:i}=await Z(e,t);this.updateTokensAndExpiration(n,r,Number(i))}updateTokensAndExpiration(e,t,n){this.refreshToken=t||null,this.accessToken=e||null,this.expirationTime=Date.now()+1e3*n}static fromJSON(e,t){let{refreshToken:n,accessToken:r,expirationTime:i}=t,s=new ee;return n&&(b("string"==typeof n,"internal-error",{appName:e}),s.refreshToken=n),r&&(b("string"==typeof r,"internal-error",{appName:e}),s.accessToken=r),i&&(b("number"==typeof i,"internal-error",{appName:e}),s.expirationTime=i),s}toJSON(){return{refreshToken:this.refreshToken,accessToken:this.accessToken,expirationTime:this.expirationTime}}_assign(e){this.accessToken=e.accessToken,this.refreshToken=e.refreshToken,this.expirationTime=e.expirationTime}_clone(){return Object.assign(new ee,this.toJSON())}_performRefresh(){return I("not implemented")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function et(e,t){b("string"==typeof e||void 0===e,"internal-error",{appName:t})}class en{constructor(e){var{uid:t,auth:n,stsTokenManager:r}=e,i=o(e,["uid","auth","stsTokenManager"]);this.providerId="firebase",this.proactiveRefresh=new Q(this),this.reloadUserInfo=null,this.reloadListener=null,this.uid=t,this.auth=n,this.stsTokenManager=r,this.accessToken=r.accessToken,this.displayName=i.displayName||null,this.email=i.email||null,this.emailVerified=i.emailVerified||!1,this.phoneNumber=i.phoneNumber||null,this.photoURL=i.photoURL||null,this.isAnonymous=i.isAnonymous||!1,this.tenantId=i.tenantId||null,this.providerData=i.providerData?[...i.providerData]:[],this.metadata=new Y(i.createdAt||void 0,i.lastLoginAt||void 0)}async getIdToken(e){let t=await H(this,this.stsTokenManager.getToken(this.auth,e));return b(t,this.auth,"internal-error"),this.accessToken!==t&&(this.accessToken=t,await this.auth._persistUserIfCurrent(this),this.auth._notifyListenersIfCurrent(this)),t}getIdTokenResult(e){return G(this,e)}reload(){return J(this)}_assign(e){this!==e&&(b(this.uid===e.uid,this.auth,"internal-error"),this.displayName=e.displayName,this.photoURL=e.photoURL,this.email=e.email,this.emailVerified=e.emailVerified,this.phoneNumber=e.phoneNumber,this.isAnonymous=e.isAnonymous,this.tenantId=e.tenantId,this.providerData=e.providerData.map(e=>Object.assign({},e)),this.metadata._copy(e.metadata),this.stsTokenManager._assign(e.stsTokenManager))}_clone(e){return new en(Object.assign(Object.assign({},this),{auth:e,stsTokenManager:this.stsTokenManager._clone()}))}_onReload(e){b(!this.reloadListener,this.auth,"internal-error"),this.reloadListener=e,this.reloadUserInfo&&(this._notifyReloadListener(this.reloadUserInfo),this.reloadUserInfo=null)}_notifyReloadListener(e){this.reloadListener?this.reloadListener(e):this.reloadUserInfo=e}_startProactiveRefresh(){this.proactiveRefresh._start()}_stopProactiveRefresh(){this.proactiveRefresh._stop()}async _updateTokensIfNecessary(e,t=!1){let n=!1;e.idToken&&e.idToken!==this.stsTokenManager.accessToken&&(this.stsTokenManager.updateFromServerResponse(e),n=!0),t&&await X(this),await this.auth._persistUserIfCurrent(this),n&&this.auth._notifyListenersIfCurrent(this)}async delete(){let e=await this.getIdToken();return await H(this,B(this.auth,{idToken:e})),this.stsTokenManager.clearRefreshToken(),this.auth.signOut()}toJSON(){return Object.assign(Object.assign({uid:this.uid,email:this.email||void 0,emailVerified:this.emailVerified,displayName:this.displayName||void 0,isAnonymous:this.isAnonymous,photoURL:this.photoURL||void 0,phoneNumber:this.phoneNumber||void 0,tenantId:this.tenantId||void 0,providerData:this.providerData.map(e=>Object.assign({},e)),stsTokenManager:this.stsTokenManager.toJSON(),_redirectEventId:this._redirectEventId},this.metadata.toJSON()),{apiKey:this.auth.config.apiKey,appName:this.auth.name})}get refreshToken(){return this.stsTokenManager.refreshToken||""}static _fromJSON(e,t){var n,r,i,s,a,o,l,u;let c=null!==(n=t.displayName)&&void 0!==n?n:void 0,h=null!==(r=t.email)&&void 0!==r?r:void 0,d=null!==(i=t.phoneNumber)&&void 0!==i?i:void 0,f=null!==(s=t.photoURL)&&void 0!==s?s:void 0,p=null!==(a=t.tenantId)&&void 0!==a?a:void 0,m=null!==(o=t._redirectEventId)&&void 0!==o?o:void 0,g=null!==(l=t.createdAt)&&void 0!==l?l:void 0,y=null!==(u=t.lastLoginAt)&&void 0!==u?u:void 0,{uid:v,emailVerified:w,isAnonymous:_,providerData:I,stsTokenManager:T}=t;b(v&&T,e,"internal-error");let E=ee.fromJSON(this.name,T);b("string"==typeof v,e,"internal-error"),et(c,e.name),et(h,e.name),b("boolean"==typeof w,e,"internal-error"),b("boolean"==typeof _,e,"internal-error"),et(d,e.name),et(f,e.name),et(p,e.name),et(m,e.name),et(g,e.name),et(y,e.name);let S=new en({uid:v,auth:e,email:h,emailVerified:w,displayName:c,isAnonymous:_,photoURL:f,phoneNumber:d,tenantId:p,stsTokenManager:E,createdAt:g,lastLoginAt:y});return I&&Array.isArray(I)&&(S.providerData=I.map(e=>Object.assign({},e))),m&&(S._redirectEventId=m),S}static async _fromIdTokenResponse(e,t,n=!1){let r=new ee;r.updateFromServerResponse(t);let i=new en({uid:t.localId,auth:e,stsTokenManager:r,isAnonymous:n});return await X(i),i}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class er{constructor(){this.type="NONE",this.storage={}}async _isAvailable(){return!0}async _set(e,t){this.storage[e]=t}async _get(e){let t=this.storage[e];return void 0===t?null:t}async _remove(e){delete this.storage[e]}_addListener(e,t){}_removeListener(e,t){}}er.type="NONE";let ei=er;/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function es(e,t,n){return`firebase:${e}:${t}:${n}`}class ea{constructor(e,t,n){this.persistence=e,this.auth=t,this.userKey=n;let{config:r,name:i}=this.auth;this.fullUserKey=es(this.userKey,r.apiKey,i),this.fullPersistenceKey=es("persistence",r.apiKey,i),this.boundEventHandler=t._onStorageEvent.bind(t),this.persistence._addListener(this.fullUserKey,this.boundEventHandler)}setCurrentUser(e){return this.persistence._set(this.fullUserKey,e.toJSON())}async getCurrentUser(){let e=await this.persistence._get(this.fullUserKey);return e?en._fromJSON(this.auth,e):null}removeCurrentUser(){return this.persistence._remove(this.fullUserKey)}savePersistenceForRedirect(){return this.persistence._set(this.fullPersistenceKey,this.persistence.type)}async setPersistence(e){if(this.persistence===e)return;let t=await this.getCurrentUser();if(await this.removeCurrentUser(),this.persistence=e,t)return this.setCurrentUser(t)}delete(){this.persistence._removeListener(this.fullUserKey,this.boundEventHandler)}static async create(e,t,n="authUser"){if(!t.length)return new ea(S(ei),e,n);let r=(await Promise.all(t.map(async e=>{if(await e._isAvailable())return e}))).filter(e=>e),i=r[0]||S(ei),s=es(n,e.config.apiKey,e.name),a=null;for(let n of t)try{let t=await n._get(s);if(t){let r=en._fromJSON(e,t);n!==i&&(a=r),i=n;break}}catch(e){}let o=r.filter(e=>e._shouldAllowMigration);return i._shouldAllowMigration&&o.length&&(i=o[0],a&&await i._set(s,a.toJSON()),await Promise.all(t.map(async e=>{if(e!==i)try{await e._remove(s)}catch(e){}}))),new ea(i,e,n)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function eo(e){let t=e.toLowerCase();if(t.includes("opera/")||t.includes("opr/")||t.includes("opios/"))return"Opera";if(eh(t))return"IEMobile";if(t.includes("msie")||t.includes("trident/"))return"IE";{if(t.includes("edge/"))return"Edge";if(el(t))return"Firefox";if(t.includes("silk/"))return"Silk";if(ef(t))return"Blackberry";if(ep(t))return"Webos";if(eu(t))return"Safari";if((t.includes("chrome/")||ec(t))&&!t.includes("edge/"))return"Chrome";if(ed(t))return"Android";let n=e.match(/([a-zA-Z\d\.]+)\/[a-zA-Z\d\.]*$/);if((null==n?void 0:n.length)===2)return n[1]}return"Other"}function el(e=(0,i.z$)()){return/firefox\//i.test(e)}function eu(e=(0,i.z$)()){let t=e.toLowerCase();return t.includes("safari/")&&!t.includes("chrome/")&&!t.includes("crios/")&&!t.includes("android")}function ec(e=(0,i.z$)()){return/crios\//i.test(e)}function eh(e=(0,i.z$)()){return/iemobile/i.test(e)}function ed(e=(0,i.z$)()){return/android/i.test(e)}function ef(e=(0,i.z$)()){return/blackberry/i.test(e)}function ep(e=(0,i.z$)()){return/webos/i.test(e)}function em(e=(0,i.z$)()){return/iphone|ipad|ipod/i.test(e)||/macintosh/i.test(e)&&/mobile/i.test(e)}function eg(e=(0,i.z$)()){return/(iPad|iPhone|iPod).*OS 7_\d/i.test(e)||/(iPad|iPhone|iPod).*OS 8_\d/i.test(e)}function ey(e=(0,i.z$)()){return em(e)||ed(e)||ep(e)||ef(e)||/windows phone/i.test(e)||eh(e)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ev(e,t=[]){let n;switch(e){case"Browser":n=eo((0,i.z$)());break;case"Worker":n=`${eo((0,i.z$)())}-${e}`;break;default:n=e}let r=t.length?t.join(","):"FirebaseCore-web";return`${n}/JsCore/${s.SDK_VERSION}/${r}`}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ew{constructor(e){this.auth=e,this.queue=[]}pushCallback(e,t){let n=t=>new Promise((n,r)=>{try{let r=e(t);n(r)}catch(e){r(e)}});n.onAbort=t,this.queue.push(n);let r=this.queue.length-1;return()=>{this.queue[r]=()=>Promise.resolve()}}async runMiddleware(e){if(this.auth.currentUser===e)return;let t=[];try{for(let n of this.queue)await n(e),n.onAbort&&t.push(n.onAbort)}catch(e){for(let e of(t.reverse(),t))try{e()}catch(e){}throw this.auth._errorFactory.create("login-blocked",{originalMessage:null==e?void 0:e.message})}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e_{constructor(e,t,n){this.app=e,this.heartbeatServiceProvider=t,this.config=n,this.currentUser=null,this.emulatorConfig=null,this.operations=Promise.resolve(),this.authStateSubscription=new eI(this),this.idTokenSubscription=new eI(this),this.beforeStateQueue=new ew(this),this.redirectUser=null,this.isProactiveRefreshEnabled=!1,this._canInitEmulator=!0,this._isInitialized=!1,this._deleted=!1,this._initializationPromise=null,this._popupRedirectResolver=null,this._errorFactory=f,this.lastNotifiedUid=void 0,this.languageCode=null,this.tenantId=null,this.settings={appVerificationDisabledForTesting:!1},this.frameworks=[],this.name=e.name,this.clientVersion=n.sdkClientVersion}_initializeWithPersistence(e,t){return t&&(this._popupRedirectResolver=S(t)),this._initializationPromise=this.queue(async()=>{var n,r;if(!this._deleted&&(this.persistenceManager=await ea.create(this,e),!this._deleted)){if(null===(n=this._popupRedirectResolver)||void 0===n?void 0:n._shouldInitProactively)try{await this._popupRedirectResolver._initialize(this)}catch(e){}await this.initializeCurrentUser(t),this.lastNotifiedUid=(null===(r=this.currentUser)||void 0===r?void 0:r.uid)||null,this._deleted||(this._isInitialized=!0)}}),this._initializationPromise}async _onStorageEvent(){if(this._deleted)return;let e=await this.assertedPersistence.getCurrentUser();if(this.currentUser||e){if(this.currentUser&&e&&this.currentUser.uid===e.uid){this._currentUser._assign(e),await this.currentUser.getIdToken();return}await this._updateCurrentUser(e,!0)}}async initializeCurrentUser(e){var t;let n=await this.assertedPersistence.getCurrentUser(),r=n,i=!1;if(e&&this.config.authDomain){await this.getOrInitRedirectPersistenceManager();let n=null===(t=this.redirectUser)||void 0===t?void 0:t._redirectEventId,s=null==r?void 0:r._redirectEventId,a=await this.tryRedirectSignIn(e);(!n||n===s)&&(null==a?void 0:a.user)&&(r=a.user,i=!0)}if(!r)return this.directlySetCurrentUser(null);if(!r._redirectEventId){if(i)try{await this.beforeStateQueue.runMiddleware(r)}catch(e){r=n,this._popupRedirectResolver._overrideRedirectResult(this,()=>Promise.reject(e))}return r?this.reloadAndSetCurrentUserOrClear(r):this.directlySetCurrentUser(null)}return(b(this._popupRedirectResolver,this,"argument-error"),await this.getOrInitRedirectPersistenceManager(),this.redirectUser&&this.redirectUser._redirectEventId===r._redirectEventId)?this.directlySetCurrentUser(r):this.reloadAndSetCurrentUserOrClear(r)}async tryRedirectSignIn(e){let t=null;try{t=await this._popupRedirectResolver._completeRedirectFn(this,e,!0)}catch(e){await this._setRedirectUser(null)}return t}async reloadAndSetCurrentUserOrClear(e){try{await X(e)}catch(e){if((null==e?void 0:e.code)!=="auth/network-request-failed")return this.directlySetCurrentUser(null)}return this.directlySetCurrentUser(e)}useDeviceLanguage(){this.languageCode=function(){if("undefined"==typeof navigator)return null;let e=navigator;return e.languages&&e.languages[0]||e.language||null}()}async _delete(){this._deleted=!0}async updateCurrentUser(e){let t=e?(0,i.m9)(e):null;return t&&b(t.auth.config.apiKey===this.config.apiKey,this,"invalid-user-token"),this._updateCurrentUser(t&&t._clone(this))}async _updateCurrentUser(e,t=!1){if(!this._deleted)return e&&b(this.tenantId===e.tenantId,this,"tenant-id-mismatch"),t||await this.beforeStateQueue.runMiddleware(e),this.queue(async()=>{await this.directlySetCurrentUser(e),this.notifyAuthListeners()})}async signOut(){return await this.beforeStateQueue.runMiddleware(null),(this.redirectPersistenceManager||this._popupRedirectResolver)&&await this._setRedirectUser(null),this._updateCurrentUser(null,!0)}setPersistence(e){return this.queue(async()=>{await this.assertedPersistence.setPersistence(S(e))})}_getPersistence(){return this.assertedPersistence.persistence.type}_updateErrorMap(e){this._errorFactory=new i.LL("auth","Firebase",e())}onAuthStateChanged(e,t,n){return this.registerStateListener(this.authStateSubscription,e,t,n)}beforeAuthStateChanged(e,t){return this.beforeStateQueue.pushCallback(e,t)}onIdTokenChanged(e,t,n){return this.registerStateListener(this.idTokenSubscription,e,t,n)}toJSON(){var e;return{apiKey:this.config.apiKey,authDomain:this.config.authDomain,appName:this.name,currentUser:null===(e=this._currentUser)||void 0===e?void 0:e.toJSON()}}async _setRedirectUser(e,t){let n=await this.getOrInitRedirectPersistenceManager(t);return null===e?n.removeCurrentUser():n.setCurrentUser(e)}async getOrInitRedirectPersistenceManager(e){if(!this.redirectPersistenceManager){let t=e&&S(e)||this._popupRedirectResolver;b(t,this,"argument-error"),this.redirectPersistenceManager=await ea.create(this,[S(t._redirectPersistence)],"redirectUser"),this.redirectUser=await this.redirectPersistenceManager.getCurrentUser()}return this.redirectPersistenceManager}async _redirectUserForId(e){var t,n;return(this._isInitialized&&await this.queue(async()=>{}),(null===(t=this._currentUser)||void 0===t?void 0:t._redirectEventId)===e)?this._currentUser:(null===(n=this.redirectUser)||void 0===n?void 0:n._redirectEventId)===e?this.redirectUser:null}async _persistUserIfCurrent(e){if(e===this.currentUser)return this.queue(async()=>this.directlySetCurrentUser(e))}_notifyListenersIfCurrent(e){e===this.currentUser&&this.notifyAuthListeners()}_key(){return`${this.config.authDomain}:${this.config.apiKey}:${this.name}`}_startProactiveRefresh(){this.isProactiveRefreshEnabled=!0,this.currentUser&&this._currentUser._startProactiveRefresh()}_stopProactiveRefresh(){this.isProactiveRefreshEnabled=!1,this.currentUser&&this._currentUser._stopProactiveRefresh()}get _currentUser(){return this.currentUser}notifyAuthListeners(){var e,t;if(!this._isInitialized)return;this.idTokenSubscription.next(this.currentUser);let n=null!==(t=null===(e=this.currentUser)||void 0===e?void 0:e.uid)&&void 0!==t?t:null;this.lastNotifiedUid!==n&&(this.lastNotifiedUid=n,this.authStateSubscription.next(this.currentUser))}registerStateListener(e,t,n,r){if(this._deleted)return()=>{};let i="function"==typeof t?t:t.next.bind(t),s=this._isInitialized?Promise.resolve():this._initializationPromise;return(b(s,this,"internal-error"),s.then(()=>i(this.currentUser)),"function"==typeof t)?e.addObserver(t,n,r):e.addObserver(t)}async directlySetCurrentUser(e){this.currentUser&&this.currentUser!==e&&this._currentUser._stopProactiveRefresh(),e&&this.isProactiveRefreshEnabled&&e._startProactiveRefresh(),this.currentUser=e,e?await this.assertedPersistence.setCurrentUser(e):await this.assertedPersistence.removeCurrentUser()}queue(e){return this.operations=this.operations.then(e,e),this.operations}get assertedPersistence(){return b(this.persistenceManager,this,"internal-error"),this.persistenceManager}_logFramework(e){!e||this.frameworks.includes(e)||(this.frameworks.push(e),this.frameworks.sort(),this.clientVersion=ev(this.config.clientPlatform,this._getFrameworks()))}_getFrameworks(){return this.frameworks}async _getAdditionalHeaders(){var e;let t={"X-Client-Version":this.clientVersion};this.app.options.appId&&(t["X-Firebase-gmpid"]=this.app.options.appId);let n=await (null===(e=this.heartbeatServiceProvider.getImmediate({optional:!0}))||void 0===e?void 0:e.getHeartbeatsHeader());return n&&(t["X-Firebase-Client"]=n),t}}function eb(e){return(0,i.m9)(e)}class eI{constructor(e){this.auth=e,this.observer=null,this.addObserver=(0,i.ne)(e=>this.observer=e)}get next(){return b(this.observer,this.auth,"internal-error"),this.observer.next.bind(this.observer)}}function eT(e,t,n){let r=eb(e);b(r._canInitEmulator,r,"emulator-config-failed"),b(/^https?:\/\//.test(t),r,"invalid-emulator-scheme");let i=!!(null==n?void 0:n.disableWarnings),s=eE(t),{host:a,port:o}=function(e){let t=eE(e),n=/(\/\/)?([^?#/]+)/.exec(e.substr(t.length));if(!n)return{host:"",port:null};let r=n[2].split("@").pop()||"",i=/^(\[[^\]]+\])(:|$)/.exec(r);if(i){let e=i[1];return{host:e,port:eS(r.substr(e.length+1))}}{let[e,t]=r.split(":");return{host:e,port:eS(t)}}}(t),l=null===o?"":`:${o}`;r.config.emulator={url:`${s}//${a}${l}/`},r.settings.appVerificationDisabledForTesting=!0,r.emulatorConfig=Object.freeze({host:a,port:o,protocol:s.replace(":",""),options:Object.freeze({disableWarnings:i})}),i||function(){function e(){let e=document.createElement("p"),t=e.style;e.innerText="Running in emulator mode. Do not use with production credentials.",t.position="fixed",t.width="100%",t.backgroundColor="#ffffff",t.border=".1em solid #000000",t.color="#b50000",t.bottom="0px",t.left="0px",t.margin="0px",t.zIndex="10000",t.textAlign="center",e.classList.add("firebase-emulator-warning"),document.body.appendChild(e)}"undefined"!=typeof console&&"function"==typeof console.info&&console.info("WARNING: You are using the Auth Emulator, which is intended for local testing only.  Do not use with production credentials."),"undefined"!=typeof window&&"undefined"!=typeof document&&("loading"===document.readyState?window.addEventListener("DOMContentLoaded",e):e())}()}function eE(e){let t=e.indexOf(":");return t<0?"":e.substr(0,t+1)}function eS(e){if(!e)return null;let t=Number(e);return isNaN(t)?null:t}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ek{constructor(e,t){this.providerId=e,this.signInMethod=t}toJSON(){return I("not implemented")}_getIdTokenResponse(e){return I("not implemented")}_linkToIdToken(e,t){return I("not implemented")}_getReauthenticationResolver(e){return I("not implemented")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eA(e,t){return L(e,"POST","/v1/accounts:resetPassword",P(e,t))}async function eC(e,t){return L(e,"POST","/v1/accounts:update",t)}async function ex(e,t){return L(e,"POST","/v1/accounts:update",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eN(e,t){return U(e,"POST","/v1/accounts:signInWithPassword",P(e,t))}async function eR(e,t){return L(e,"POST","/v1/accounts:sendOobCode",P(e,t))}async function eD(e,t){return eR(e,t)}async function eO(e,t){return eR(e,t)}async function eP(e,t){return eR(e,t)}async function eL(e,t){return eR(e,t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eM(e,t){return U(e,"POST","/v1/accounts:signInWithEmailLink",P(e,t))}async function eU(e,t){return U(e,"POST","/v1/accounts:signInWithEmailLink",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eF extends ek{constructor(e,t,n,r=null){super("password",n),this._email=e,this._password=t,this._tenantId=r}static _fromEmailAndPassword(e,t){return new eF(e,t,"password")}static _fromEmailAndCode(e,t,n=null){return new eF(e,t,"emailLink",n)}toJSON(){return{email:this._email,password:this._password,signInMethod:this.signInMethod,tenantId:this._tenantId}}static fromJSON(e){let t="string"==typeof e?JSON.parse(e):e;if((null==t?void 0:t.email)&&(null==t?void 0:t.password)){if("password"===t.signInMethod)return this._fromEmailAndPassword(t.email,t.password);if("emailLink"===t.signInMethod)return this._fromEmailAndCode(t.email,t.password,t.tenantId)}return null}async _getIdTokenResponse(e){switch(this.signInMethod){case"password":return eN(e,{returnSecureToken:!0,email:this._email,password:this._password});case"emailLink":return eM(e,{email:this._email,oobCode:this._password});default:g(e,"internal-error")}}async _linkToIdToken(e,t){switch(this.signInMethod){case"password":return eC(e,{idToken:t,returnSecureToken:!0,email:this._email,password:this._password});case"emailLink":return eU(e,{idToken:t,email:this._email,oobCode:this._password});default:g(e,"internal-error")}}_getReauthenticationResolver(e){return this._getIdTokenResponse(e)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eV(e,t){return U(e,"POST","/v1/accounts:signInWithIdp",P(e,t))}class eq extends ek{constructor(){super(...arguments),this.pendingToken=null}static _fromParams(e){let t=new eq(e.providerId,e.signInMethod);return e.idToken||e.accessToken?(e.idToken&&(t.idToken=e.idToken),e.accessToken&&(t.accessToken=e.accessToken),e.nonce&&!e.pendingToken&&(t.nonce=e.nonce),e.pendingToken&&(t.pendingToken=e.pendingToken)):e.oauthToken&&e.oauthTokenSecret?(t.accessToken=e.oauthToken,t.secret=e.oauthTokenSecret):g("argument-error"),t}toJSON(){return{idToken:this.idToken,accessToken:this.accessToken,secret:this.secret,nonce:this.nonce,pendingToken:this.pendingToken,providerId:this.providerId,signInMethod:this.signInMethod}}static fromJSON(e){let t="string"==typeof e?JSON.parse(e):e,{providerId:n,signInMethod:r}=t,i=o(t,["providerId","signInMethod"]);if(!n||!r)return null;let s=new eq(n,r);return s.idToken=i.idToken||void 0,s.accessToken=i.accessToken||void 0,s.secret=i.secret,s.nonce=i.nonce,s.pendingToken=i.pendingToken||null,s}_getIdTokenResponse(e){let t=this.buildRequest();return eV(e,t)}_linkToIdToken(e,t){let n=this.buildRequest();return n.idToken=t,eV(e,n)}_getReauthenticationResolver(e){let t=this.buildRequest();return t.autoCreate=!1,eV(e,t)}buildRequest(){let e={requestUri:"http://localhost",returnSecureToken:!0};if(this.pendingToken)e.pendingToken=this.pendingToken;else{let t={};this.idToken&&(t.id_token=this.idToken),this.accessToken&&(t.access_token=this.accessToken),this.secret&&(t.oauth_token_secret=this.secret),t.providerId=this.providerId,this.nonce&&!this.pendingToken&&(t.nonce=this.nonce),e.postBody=(0,i.xO)(t)}return e}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eB(e,t){return L(e,"POST","/v1/accounts:sendVerificationCode",P(e,t))}async function ej(e,t){return U(e,"POST","/v1/accounts:signInWithPhoneNumber",P(e,t))}async function ez(e,t){let n=await U(e,"POST","/v1/accounts:signInWithPhoneNumber",P(e,t));if(n.temporaryProof)throw q(e,"account-exists-with-different-credential",n);return n}let e$={USER_NOT_FOUND:"user-not-found"};async function eG(e,t){let n=Object.assign(Object.assign({},t),{operation:"REAUTH"});return U(e,"POST","/v1/accounts:signInWithPhoneNumber",P(e,n),e$)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eK extends ek{constructor(e){super("phone","phone"),this.params=e}static _fromVerification(e,t){return new eK({verificationId:e,verificationCode:t})}static _fromTokenResponse(e,t){return new eK({phoneNumber:e,temporaryProof:t})}_getIdTokenResponse(e){return ej(e,this._makeVerificationRequest())}_linkToIdToken(e,t){return ez(e,Object.assign({idToken:t},this._makeVerificationRequest()))}_getReauthenticationResolver(e){return eG(e,this._makeVerificationRequest())}_makeVerificationRequest(){let{temporaryProof:e,phoneNumber:t,verificationId:n,verificationCode:r}=this.params;return e&&t?{temporaryProof:e,phoneNumber:t}:{sessionInfo:n,code:r}}toJSON(){let e={providerId:this.providerId};return this.params.phoneNumber&&(e.phoneNumber=this.params.phoneNumber),this.params.temporaryProof&&(e.temporaryProof=this.params.temporaryProof),this.params.verificationCode&&(e.verificationCode=this.params.verificationCode),this.params.verificationId&&(e.verificationId=this.params.verificationId),e}static fromJSON(e){"string"==typeof e&&(e=JSON.parse(e));let{verificationId:t,verificationCode:n,phoneNumber:r,temporaryProof:i}=e;return n||t||r||i?new eK({verificationId:t,verificationCode:n,phoneNumber:r,temporaryProof:i}):null}}class eW{constructor(e){var t,n,r,s,a,o;let l=(0,i.zd)((0,i.pd)(e)),u=null!==(t=l.apiKey)&&void 0!==t?t:null,c=null!==(n=l.oobCode)&&void 0!==n?n:null,h=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){switch(e){case"recoverEmail":return"RECOVER_EMAIL";case"resetPassword":return"PASSWORD_RESET";case"signIn":return"EMAIL_SIGNIN";case"verifyEmail":return"VERIFY_EMAIL";case"verifyAndChangeEmail":return"VERIFY_AND_CHANGE_EMAIL";case"revertSecondFactorAddition":return"REVERT_SECOND_FACTOR_ADDITION";default:return null}}(null!==(r=l.mode)&&void 0!==r?r:null);b(u&&c&&h,"argument-error"),this.apiKey=u,this.operation=h,this.code=c,this.continueUrl=null!==(s=l.continueUrl)&&void 0!==s?s:null,this.languageCode=null!==(a=l.languageCode)&&void 0!==a?a:null,this.tenantId=null!==(o=l.tenantId)&&void 0!==o?o:null}static parseLink(e){let t=function(e){let t=(0,i.zd)((0,i.pd)(e)).link,n=t?(0,i.zd)((0,i.pd)(t)).deep_link_id:null,r=(0,i.zd)((0,i.pd)(e)).deep_link_id,s=r?(0,i.zd)((0,i.pd)(r)).link:null;return s||r||n||t||e}(e);try{return new eW(t)}catch(e){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eH{constructor(){this.providerId=eH.PROVIDER_ID}static credential(e,t){return eF._fromEmailAndPassword(e,t)}static credentialWithLink(e,t){let n=eW.parseLink(t);return b(n,"argument-error"),eF._fromEmailAndCode(e,n.code,n.tenantId)}}eH.PROVIDER_ID="password",eH.EMAIL_PASSWORD_SIGN_IN_METHOD="password",eH.EMAIL_LINK_SIGN_IN_METHOD="emailLink";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eQ{constructor(e){this.providerId=e,this.defaultLanguageCode=null,this.customParameters={}}setDefaultLanguage(e){this.defaultLanguageCode=e}setCustomParameters(e){return this.customParameters=e,this}getCustomParameters(){return this.customParameters}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eY extends eQ{constructor(){super(...arguments),this.scopes=[]}addScope(e){return this.scopes.includes(e)||this.scopes.push(e),this}getScopes(){return[...this.scopes]}}class eX extends eY{static credentialFromJSON(e){let t="string"==typeof e?JSON.parse(e):e;return b("providerId"in t&&"signInMethod"in t,"argument-error"),eq._fromParams(t)}credential(e){return this._credential(Object.assign(Object.assign({},e),{nonce:e.rawNonce}))}_credential(e){return b(e.idToken||e.accessToken,"argument-error"),eq._fromParams(Object.assign(Object.assign({},e),{providerId:this.providerId,signInMethod:this.providerId}))}static credentialFromResult(e){return eX.oauthCredentialFromTaggedObject(e)}static credentialFromError(e){return eX.oauthCredentialFromTaggedObject(e.customData||{})}static oauthCredentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{oauthIdToken:t,oauthAccessToken:n,oauthTokenSecret:r,pendingToken:i,nonce:s,providerId:a}=e;if(!n&&!r&&!t&&!i||!a)return null;try{return new eX(a)._credential({idToken:t,accessToken:n,nonce:s,pendingToken:i})}catch(e){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eJ extends eY{constructor(){super("facebook.com")}static credential(e){return eq._fromParams({providerId:eJ.PROVIDER_ID,signInMethod:eJ.FACEBOOK_SIGN_IN_METHOD,accessToken:e})}static credentialFromResult(e){return eJ.credentialFromTaggedObject(e)}static credentialFromError(e){return eJ.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e||!("oauthAccessToken"in e)||!e.oauthAccessToken)return null;try{return eJ.credential(e.oauthAccessToken)}catch(e){return null}}}eJ.FACEBOOK_SIGN_IN_METHOD="facebook.com",eJ.PROVIDER_ID="facebook.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eZ extends eY{constructor(){super("google.com"),this.addScope("profile")}static credential(e,t){return eq._fromParams({providerId:eZ.PROVIDER_ID,signInMethod:eZ.GOOGLE_SIGN_IN_METHOD,idToken:e,accessToken:t})}static credentialFromResult(e){return eZ.credentialFromTaggedObject(e)}static credentialFromError(e){return eZ.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{oauthIdToken:t,oauthAccessToken:n}=e;if(!t&&!n)return null;try{return eZ.credential(t,n)}catch(e){return null}}}eZ.GOOGLE_SIGN_IN_METHOD="google.com",eZ.PROVIDER_ID="google.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e0 extends eY{constructor(){super("github.com")}static credential(e){return eq._fromParams({providerId:e0.PROVIDER_ID,signInMethod:e0.GITHUB_SIGN_IN_METHOD,accessToken:e})}static credentialFromResult(e){return e0.credentialFromTaggedObject(e)}static credentialFromError(e){return e0.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e||!("oauthAccessToken"in e)||!e.oauthAccessToken)return null;try{return e0.credential(e.oauthAccessToken)}catch(e){return null}}}e0.GITHUB_SIGN_IN_METHOD="github.com",e0.PROVIDER_ID="github.com";class e1 extends ek{constructor(e,t){super(e,e),this.pendingToken=t}_getIdTokenResponse(e){let t=this.buildRequest();return eV(e,t)}_linkToIdToken(e,t){let n=this.buildRequest();return n.idToken=t,eV(e,n)}_getReauthenticationResolver(e){let t=this.buildRequest();return t.autoCreate=!1,eV(e,t)}toJSON(){return{signInMethod:this.signInMethod,providerId:this.providerId,pendingToken:this.pendingToken}}static fromJSON(e){let t="string"==typeof e?JSON.parse(e):e,{providerId:n,signInMethod:r,pendingToken:i}=t;return n&&r&&i&&n===r?new e1(n,i):null}static _create(e,t){return new e1(e,t)}buildRequest(){return{requestUri:"http://localhost",returnSecureToken:!0,pendingToken:this.pendingToken}}}class e2 extends eQ{constructor(e){b(e.startsWith("saml."),"argument-error"),super(e)}static credentialFromResult(e){return e2.samlCredentialFromTaggedObject(e)}static credentialFromError(e){return e2.samlCredentialFromTaggedObject(e.customData||{})}static credentialFromJSON(e){let t=e1.fromJSON(e);return b(t,"argument-error"),t}static samlCredentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{pendingToken:t,providerId:n}=e;if(!t||!n)return null;try{return e1._create(n,t)}catch(e){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e3 extends eY{constructor(){super("twitter.com")}static credential(e,t){return eq._fromParams({providerId:e3.PROVIDER_ID,signInMethod:e3.TWITTER_SIGN_IN_METHOD,oauthToken:e,oauthTokenSecret:t})}static credentialFromResult(e){return e3.credentialFromTaggedObject(e)}static credentialFromError(e){return e3.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{oauthAccessToken:t,oauthTokenSecret:n}=e;if(!t||!n)return null;try{return e3.credential(t,n)}catch(e){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function e4(e,t){return U(e,"POST","/v1/accounts:signUp",P(e,t))}e3.TWITTER_SIGN_IN_METHOD="twitter.com",e3.PROVIDER_ID="twitter.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e6{constructor(e){this.user=e.user,this.providerId=e.providerId,this._tokenResponse=e._tokenResponse,this.operationType=e.operationType}static async _fromIdTokenResponse(e,t,n,r=!1){let i=await en._fromIdTokenResponse(e,n,r),s=e5(n),a=new e6({user:i,providerId:s,_tokenResponse:n,operationType:t});return a}static async _forOperation(e,t,n){await e._updateTokensIfNecessary(n,!0);let r=e5(n);return new e6({user:e,providerId:r,_tokenResponse:n,operationType:t})}}function e5(e){return e.providerId?e.providerId:"phoneNumber"in e?"phone":null}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function e9(e){var t;let n=eb(e);if(await n._initializationPromise,null===(t=n.currentUser)||void 0===t?void 0:t.isAnonymous)return new e6({user:n.currentUser,providerId:null,operationType:"signIn"});let r=await e4(n,{returnSecureToken:!0}),i=await e6._fromIdTokenResponse(n,"signIn",r,!0);return await n._updateCurrentUser(i.user),i}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e8 extends i.ZR{constructor(e,t,n,r){var i;super(t.code,t.message),this.operationType=n,this.user=r,Object.setPrototypeOf(this,e8.prototype),this.customData={appName:e.name,tenantId:null!==(i=e.tenantId)&&void 0!==i?i:void 0,_serverResponse:t.customData._serverResponse,operationType:n}}static _fromErrorAndOperation(e,t,n,r){return new e8(e,t,n,r)}}function e7(e,t,n,r){let i="reauthenticate"===t?n._getReauthenticationResolver(e):n._getIdTokenResponse(e);return i.catch(n=>{if("auth/multi-factor-auth-required"===n.code)throw e8._fromErrorAndOperation(e,n,t,r);throw n})}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function te(e){return new Set(e.map(({providerId:e})=>e).filter(e=>!!e))}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tt(e,t){let n=(0,i.m9)(e);await tr(!0,n,t);let{providerUserInfo:r}=await j(n.auth,{idToken:await n.getIdToken(),deleteProvider:[t]}),s=te(r||[]);return n.providerData=n.providerData.filter(e=>s.has(e.providerId)),s.has("phone")||(n.phoneNumber=null),await n.auth._persistUserIfCurrent(n),n}async function tn(e,t,n=!1){let r=await H(e,t._linkToIdToken(e.auth,await e.getIdToken()),n);return e6._forOperation(e,"link",r)}async function tr(e,t,n){await X(t);let r=te(t.providerData);b(r.has(n)===e,t.auth,!1===e?"provider-already-linked":"no-such-provider")}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function ti(e,t,n=!1){let{auth:r}=e,i="reauthenticate";try{let s=await H(e,e7(r,i,t,e),n);b(s.idToken,r,"internal-error");let a=W(s.idToken);b(a,r,"internal-error");let{sub:o}=a;return b(e.uid===o,r,"user-mismatch"),e6._forOperation(e,i,s)}catch(e){throw(null==e?void 0:e.code)==="auth/user-not-found"&&g(r,"user-mismatch"),e}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function ts(e,t,n=!1){let r="signIn",i=await e7(e,r,t),s=await e6._fromIdTokenResponse(e,r,i);return n||await e._updateCurrentUser(s.user),s}async function ta(e,t){return ts(eb(e),t)}async function to(e,t){let n=(0,i.m9)(e);return await tr(!1,n,t.providerId),tn(n,t)}async function tl(e,t){return ti((0,i.m9)(e),t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tu(e,t){return U(e,"POST","/v1/accounts:signInWithCustomToken",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tc(e,t){let n=eb(e),r=await tu(n,{token:t,returnSecureToken:!0}),i=await e6._fromIdTokenResponse(n,"signIn",r);return await n._updateCurrentUser(i.user),i}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class th{constructor(e,t){this.factorId=e,this.uid=t.mfaEnrollmentId,this.enrollmentTime=new Date(t.enrolledAt).toUTCString(),this.displayName=t.displayName}static _fromServerResponse(e,t){return"phoneInfo"in t?td._fromServerResponse(e,t):g(e,"internal-error")}}class td extends th{constructor(e){super("phone",e),this.phoneNumber=e.phoneInfo}static _fromServerResponse(e,t){return new td(t)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function tf(e,t,n){var r;b((null===(r=n.url)||void 0===r?void 0:r.length)>0,e,"invalid-continue-uri"),b(void 0===n.dynamicLinkDomain||n.dynamicLinkDomain.length>0,e,"invalid-dynamic-link-domain"),t.continueUrl=n.url,t.dynamicLinkDomain=n.dynamicLinkDomain,t.canHandleCodeInApp=n.handleCodeInApp,n.iOS&&(b(n.iOS.bundleId.length>0,e,"missing-ios-bundle-id"),t.iOSBundleId=n.iOS.bundleId),n.android&&(b(n.android.packageName.length>0,e,"missing-android-pkg-name"),t.androidInstallApp=n.android.installApp,t.androidMinimumVersionCode=n.android.minimumVersion,t.androidPackageName=n.android.packageName)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tp(e,t,n){let r=(0,i.m9)(e),s={requestType:"PASSWORD_RESET",email:t};n&&tf(r,s,n),await eO(r,s)}async function tm(e,t,n){await eA((0,i.m9)(e),{oobCode:t,newPassword:n})}async function tg(e,t){await ex((0,i.m9)(e),{oobCode:t})}async function ty(e,t){let n=(0,i.m9)(e),r=await eA(n,{oobCode:t}),s=r.requestType;switch(b(s,n,"internal-error"),s){case"EMAIL_SIGNIN":break;case"VERIFY_AND_CHANGE_EMAIL":b(r.newEmail,n,"internal-error");break;case"REVERT_SECOND_FACTOR_ADDITION":b(r.mfaInfo,n,"internal-error");default:b(r.email,n,"internal-error")}let a=null;return r.mfaInfo&&(a=th._fromServerResponse(eb(n),r.mfaInfo)),{data:{email:("VERIFY_AND_CHANGE_EMAIL"===r.requestType?r.newEmail:r.email)||null,previousEmail:("VERIFY_AND_CHANGE_EMAIL"===r.requestType?r.email:r.newEmail)||null,multiFactorInfo:a},operation:s}}async function tv(e,t){let{data:n}=await ty((0,i.m9)(e),t);return n.email}async function tw(e,t,n){let r=eb(e),i=await e4(r,{returnSecureToken:!0,email:t,password:n}),s=await e6._fromIdTokenResponse(r,"signIn",i);return await r._updateCurrentUser(s.user),s}function t_(e,t,n){return ta((0,i.m9)(e),eH.credential(t,n))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tb(e,t,n){let r=(0,i.m9)(e),s={requestType:"EMAIL_SIGNIN",email:t};b(n.handleCodeInApp,r,"argument-error"),n&&tf(r,s,n),await eP(r,s)}function tI(e,t){let n=eW.parseLink(t);return(null==n?void 0:n.operation)==="EMAIL_SIGNIN"}async function tT(e,t,n){let r=(0,i.m9)(e),s=eH.credentialWithLink(t,n||k());return b(s._tenantId===(r.tenantId||null),r,"tenant-id-mismatch"),ta(r,s)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tE(e,t){return L(e,"POST","/v1/accounts:createAuthUri",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tS(e,t){let n=A()?k():"http://localhost",{signinMethods:r}=await tE((0,i.m9)(e),{identifier:t,continueUri:n});return r||[]}async function tk(e,t){let n=(0,i.m9)(e),r=await e.getIdToken(),s={requestType:"VERIFY_EMAIL",idToken:r};t&&tf(n.auth,s,t);let{email:a}=await eD(n.auth,s);a!==e.email&&await e.reload()}async function tA(e,t,n){let r=(0,i.m9)(e),s=await e.getIdToken(),a={requestType:"VERIFY_AND_CHANGE_EMAIL",idToken:s,newEmail:t};n&&tf(r.auth,a,n);let{email:o}=await eL(r.auth,a);o!==e.email&&await e.reload()}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tC(e,t){return L(e,"POST","/v1/accounts:update",t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tx(e,{displayName:t,photoURL:n}){if(void 0===t&&void 0===n)return;let r=(0,i.m9)(e),s=await r.getIdToken(),a=await H(r,tC(r.auth,{idToken:s,displayName:t,photoUrl:n,returnSecureToken:!0}));r.displayName=a.displayName||null,r.photoURL=a.photoUrl||null;let o=r.providerData.find(({providerId:e})=>"password"===e);o&&(o.displayName=r.displayName,o.photoURL=r.photoURL),await r._updateTokensIfNecessary(a)}function tN(e,t){return tD((0,i.m9)(e),t,null)}function tR(e,t){return tD((0,i.m9)(e),null,t)}async function tD(e,t,n){let{auth:r}=e,i=await e.getIdToken(),s={idToken:i,returnSecureToken:!0};t&&(s.email=t),n&&(s.password=n);let a=await H(e,eC(r,s));await e._updateTokensIfNecessary(a,!0)}class tO{constructor(e,t,n={}){this.isNewUser=e,this.providerId=t,this.profile=n}}class tP extends tO{constructor(e,t,n,r){super(e,t,n),this.username=r}}class tL extends tO{constructor(e,t){super(e,"facebook.com",t)}}class tM extends tP{constructor(e,t){super(e,"github.com",t,"string"==typeof(null==t?void 0:t.login)?null==t?void 0:t.login:null)}}class tU extends tO{constructor(e,t){super(e,"google.com",t)}}class tF extends tP{constructor(e,t,n){super(e,"twitter.com",t,n)}}function tV(e){let{user:t,_tokenResponse:n}=e;return t.isAnonymous&&!n?{providerId:null,isNewUser:!1,profile:null}:/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){var t,n;if(!e)return null;let{providerId:r}=e,i=e.rawUserInfo?JSON.parse(e.rawUserInfo):{},s=e.isNewUser||"identitytoolkit#SignupNewUserResponse"===e.kind;if(!r&&(null==e?void 0:e.idToken)){let r=null===(n=null===(t=W(e.idToken))||void 0===t?void 0:t.firebase)||void 0===n?void 0:n.sign_in_provider;if(r)return new tO(s,"anonymous"!==r&&"custom"!==r?r:null)}if(!r)return null;switch(r){case"facebook.com":return new tL(s,i);case"github.com":return new tM(s,i);case"google.com":return new tU(s,i);case"twitter.com":return new tF(s,i,e.screenName||null);case"custom":case"anonymous":return new tO(s,null);default:return new tO(s,r,i)}}(n)}function tq(e,t,n,r){return(0,i.m9)(e).onAuthStateChanged(t,n,r)}class tB{constructor(e,t,n){this.type=e,this.credential=t,this.auth=n}static _fromIdtoken(e,t){return new tB("enroll",e,t)}static _fromMfaPendingCredential(e){return new tB("signin",e)}toJSON(){let e="enroll"===this.type?"idToken":"pendingCredential";return{multiFactorSession:{[e]:this.credential}}}static fromJSON(e){var t,n;if(null==e?void 0:e.multiFactorSession){if(null===(t=e.multiFactorSession)||void 0===t?void 0:t.pendingCredential)return tB._fromMfaPendingCredential(e.multiFactorSession.pendingCredential);if(null===(n=e.multiFactorSession)||void 0===n?void 0:n.idToken)return tB._fromIdtoken(e.multiFactorSession.idToken)}return null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tj{constructor(e,t,n){this.session=e,this.hints=t,this.signInResolver=n}static _fromError(e,t){let n=eb(e),r=t.customData._serverResponse,i=(r.mfaInfo||[]).map(e=>th._fromServerResponse(n,e));b(r.mfaPendingCredential,n,"internal-error");let s=tB._fromMfaPendingCredential(r.mfaPendingCredential);return new tj(s,i,async e=>{let i=await e._process(n,s);delete r.mfaInfo,delete r.mfaPendingCredential;let a=Object.assign(Object.assign({},r),{idToken:i.idToken,refreshToken:i.refreshToken});switch(t.operationType){case"signIn":let o=await e6._fromIdTokenResponse(n,t.operationType,a);return await n._updateCurrentUser(o.user),o;case"reauthenticate":return b(t.user,n,"internal-error"),e6._forOperation(t.user,t.operationType,a);default:g(n,"internal-error")}})}async resolveSignIn(e){return this.signInResolver(e)}}function tz(e,t){var n;let r=(0,i.m9)(e);return b(t.customData.operationType,r,"argument-error"),b(null===(n=t.customData._serverResponse)||void 0===n?void 0:n.mfaPendingCredential,r,"argument-error"),tj._fromError(r,t)}class t${constructor(e){this.user=e,this.enrolledFactors=[],e._onReload(t=>{t.mfaInfo&&(this.enrolledFactors=t.mfaInfo.map(t=>th._fromServerResponse(e.auth,t)))})}static _fromUser(e){return new t$(e)}async getSession(){return tB._fromIdtoken(await this.user.getIdToken(),this.user.auth)}async enroll(e,t){let n=await this.getSession(),r=await H(this.user,e._process(this.user.auth,n,t));return await this.user._updateTokensIfNecessary(r),this.user.reload()}async unenroll(e){let t="string"==typeof e?e:e.uid,n=await this.user.getIdToken();try{var r;let e=await H(this.user,(r=this.user.auth,L(r,"POST","/v2/accounts/mfaEnrollment:withdraw",P(r,{idToken:n,mfaEnrollmentId:t}))));this.enrolledFactors=this.enrolledFactors.filter(({uid:e})=>e!==t),await this.user._updateTokensIfNecessary(e),await this.user.reload()}catch(e){throw e}}}let tG=new WeakMap;function tK(e){let t=(0,i.m9)(e);return tG.has(t)||tG.set(t,t$._fromUser(t)),tG.get(t)}let tW="__sak";/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tH{constructor(e,t){this.storageRetriever=e,this.type=t}_isAvailable(){try{if(!this.storage)return Promise.resolve(!1);return this.storage.setItem(tW,"1"),this.storage.removeItem(tW),Promise.resolve(!0)}catch(e){return Promise.resolve(!1)}}_set(e,t){return this.storage.setItem(e,JSON.stringify(t)),Promise.resolve()}_get(e){let t=this.storage.getItem(e);return Promise.resolve(t?JSON.parse(t):null)}_remove(e){return this.storage.removeItem(e),Promise.resolve()}get storage(){return this.storageRetriever()}}class tQ extends tH{constructor(){super(()=>window.localStorage,"LOCAL"),this.boundEventHandler=(e,t)=>this.onStorageEvent(e,t),this.listeners={},this.localCache={},this.pollTimer=null,this.safariLocalStorageNotSynced=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(){let e=(0,i.z$)();return eu(e)||em(e)}()&&function(){try{return!!(window&&window!==window.top)}catch(e){return!1}}(),this.fallbackToPolling=ey(),this._shouldAllowMigration=!0}forAllChangedKeys(e){for(let t of Object.keys(this.listeners)){let n=this.storage.getItem(t),r=this.localCache[t];n!==r&&e(t,r,n)}}onStorageEvent(e,t=!1){if(!e.key){this.forAllChangedKeys((e,t,n)=>{this.notifyListeners(e,n)});return}let n=e.key;if(t?this.detachListener():this.stopPolling(),this.safariLocalStorageNotSynced){let r=this.storage.getItem(n);if(e.newValue!==r)null!==e.newValue?this.storage.setItem(n,e.newValue):this.storage.removeItem(n);else if(this.localCache[n]===e.newValue&&!t)return}let r=()=>{let e=this.storage.getItem(n);(t||this.localCache[n]!==e)&&this.notifyListeners(n,e)},s=this.storage.getItem(n);(0,i.w1)()&&10===document.documentMode&&s!==e.newValue&&e.newValue!==e.oldValue?setTimeout(r,10):r()}notifyListeners(e,t){this.localCache[e]=t;let n=this.listeners[e];if(n)for(let e of Array.from(n))e(t?JSON.parse(t):t)}startPolling(){this.stopPolling(),this.pollTimer=setInterval(()=>{this.forAllChangedKeys((e,t,n)=>{this.onStorageEvent(new StorageEvent("storage",{key:e,oldValue:t,newValue:n}),!0)})},1e3)}stopPolling(){this.pollTimer&&(clearInterval(this.pollTimer),this.pollTimer=null)}attachListener(){window.addEventListener("storage",this.boundEventHandler)}detachListener(){window.removeEventListener("storage",this.boundEventHandler)}_addListener(e,t){0===Object.keys(this.listeners).length&&(this.fallbackToPolling?this.startPolling():this.attachListener()),this.listeners[e]||(this.listeners[e]=new Set,this.localCache[e]=this.storage.getItem(e)),this.listeners[e].add(t)}_removeListener(e,t){this.listeners[e]&&(this.listeners[e].delete(t),0===this.listeners[e].size&&delete this.listeners[e]),0===Object.keys(this.listeners).length&&(this.detachListener(),this.stopPolling())}async _set(e,t){await super._set(e,t),this.localCache[e]=JSON.stringify(t)}async _get(e){let t=await super._get(e);return this.localCache[e]=JSON.stringify(t),t}async _remove(e){await super._remove(e),delete this.localCache[e]}}tQ.type="LOCAL";let tY=tQ;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tX extends tH{constructor(){super(()=>window.sessionStorage,"SESSION")}_addListener(e,t){}_removeListener(e,t){}}tX.type="SESSION";let tJ=tX;/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tZ{constructor(e){this.eventTarget=e,this.handlersMap={},this.boundEventHandler=this.handleEvent.bind(this)}static _getInstance(e){let t=this.receivers.find(t=>t.isListeningto(e));if(t)return t;let n=new tZ(e);return this.receivers.push(n),n}isListeningto(e){return this.eventTarget===e}async handleEvent(e){let{eventId:t,eventType:n,data:r}=e.data,i=this.handlersMap[n];if(!(null==i?void 0:i.size))return;e.ports[0].postMessage({status:"ack",eventId:t,eventType:n});let s=Array.from(i).map(async t=>t(e.origin,r)),a=await Promise.all(s.map(async e=>{try{let t=await e;return{fulfilled:!0,value:t}}catch(e){return{fulfilled:!1,reason:e}}}));e.ports[0].postMessage({status:"done",eventId:t,eventType:n,response:a})}_subscribe(e,t){0===Object.keys(this.handlersMap).length&&this.eventTarget.addEventListener("message",this.boundEventHandler),this.handlersMap[e]||(this.handlersMap[e]=new Set),this.handlersMap[e].add(t)}_unsubscribe(e,t){this.handlersMap[e]&&t&&this.handlersMap[e].delete(t),t&&0!==this.handlersMap[e].size||delete this.handlersMap[e],0===Object.keys(this.handlersMap).length&&this.eventTarget.removeEventListener("message",this.boundEventHandler)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function t0(e="",t=10){let n="";for(let e=0;e<t;e++)n+=Math.floor(10*Math.random());return e+n}tZ.receivers=[];/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class t1{constructor(e){this.target=e,this.handlers=new Set}removeMessageHandler(e){e.messageChannel&&(e.messageChannel.port1.removeEventListener("message",e.onMessage),e.messageChannel.port1.close()),this.handlers.delete(e)}async _send(e,t,n=50){let r,i;let s="undefined"!=typeof MessageChannel?new MessageChannel:null;if(!s)throw Error("connection_unavailable");return new Promise((a,o)=>{let l=t0("",20);s.port1.start();let u=setTimeout(()=>{o(Error("unsupported_event"))},n);i={messageChannel:s,onMessage(e){if(e.data.eventId===l)switch(e.data.status){case"ack":clearTimeout(u),r=setTimeout(()=>{o(Error("timeout"))},3e3);break;case"done":clearTimeout(r),a(e.data.response);break;default:clearTimeout(u),clearTimeout(r),o(Error("invalid_response"))}}},this.handlers.add(i),s.port1.addEventListener("message",i.onMessage),this.target.postMessage({eventType:e,eventId:l,data:t},[s.port2])}).finally(()=>{i&&this.removeMessageHandler(i)})}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function t2(){return window}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function t3(){return void 0!==t2().WorkerGlobalScope&&"function"==typeof t2().importScripts}async function t4(){if(!(null==navigator?void 0:navigator.serviceWorker))return null;try{let e=await navigator.serviceWorker.ready;return e.active}catch(e){return null}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let t6="firebaseLocalStorageDb",t5="firebaseLocalStorage",t9="fbase_key";class t8{constructor(e){this.request=e}toPromise(){return new Promise((e,t)=>{this.request.addEventListener("success",()=>{e(this.request.result)}),this.request.addEventListener("error",()=>{t(this.request.error)})})}}function t7(e,t){return e.transaction([t5],t?"readwrite":"readonly").objectStore(t5)}function ne(){let e=indexedDB.open(t6,1);return new Promise((t,n)=>{e.addEventListener("error",()=>{n(e.error)}),e.addEventListener("upgradeneeded",()=>{let t=e.result;try{t.createObjectStore(t5,{keyPath:t9})}catch(e){n(e)}}),e.addEventListener("success",async()=>{let n=e.result;n.objectStoreNames.contains(t5)?t(n):(n.close(),await function(){let e=indexedDB.deleteDatabase(t6);return new t8(e).toPromise()}(),t(await ne()))})})}async function nt(e,t,n){let r=t7(e,!0).put({[t9]:t,value:n});return new t8(r).toPromise()}async function nn(e,t){let n=t7(e,!1).get(t),r=await new t8(n).toPromise();return void 0===r?null:r.value}function nr(e,t){let n=t7(e,!0).delete(t);return new t8(n).toPromise()}class ni{constructor(){this.type="LOCAL",this._shouldAllowMigration=!0,this.listeners={},this.localCache={},this.pollTimer=null,this.pendingWrites=0,this.receiver=null,this.sender=null,this.serviceWorkerReceiverAvailable=!1,this.activeServiceWorker=null,this._workerInitializationPromise=this.initializeServiceWorkerMessaging().then(()=>{},()=>{})}async _openDb(){return this.db||(this.db=await ne()),this.db}async _withRetries(e){let t=0;for(;;)try{let t=await this._openDb();return await e(t)}catch(e){if(t++>3)throw e;this.db&&(this.db.close(),this.db=void 0)}}async initializeServiceWorkerMessaging(){return t3()?this.initializeReceiver():this.initializeSender()}async initializeReceiver(){this.receiver=tZ._getInstance(t3()?self:null),this.receiver._subscribe("keyChanged",async(e,t)=>{let n=await this._poll();return{keyProcessed:n.includes(t.key)}}),this.receiver._subscribe("ping",async(e,t)=>["keyChanged"])}async initializeSender(){var e,t;if(this.activeServiceWorker=await t4(),!this.activeServiceWorker)return;this.sender=new t1(this.activeServiceWorker);let n=await this.sender._send("ping",{},800);n&&(null===(e=n[0])||void 0===e?void 0:e.fulfilled)&&(null===(t=n[0])||void 0===t?void 0:t.value.includes("keyChanged"))&&(this.serviceWorkerReceiverAvailable=!0)}async notifyServiceWorker(e){var t;if(this.sender&&this.activeServiceWorker&&((null===(t=null==navigator?void 0:navigator.serviceWorker)||void 0===t?void 0:t.controller)||null)===this.activeServiceWorker)try{await this.sender._send("keyChanged",{key:e},this.serviceWorkerReceiverAvailable?800:50)}catch(e){}}async _isAvailable(){try{if(!indexedDB)return!1;let e=await ne();return await nt(e,tW,"1"),await nr(e,tW),!0}catch(e){}return!1}async _withPendingWrite(e){this.pendingWrites++;try{await e()}finally{this.pendingWrites--}}async _set(e,t){return this._withPendingWrite(async()=>(await this._withRetries(n=>nt(n,e,t)),this.localCache[e]=t,this.notifyServiceWorker(e)))}async _get(e){let t=await this._withRetries(t=>nn(t,e));return this.localCache[e]=t,t}async _remove(e){return this._withPendingWrite(async()=>(await this._withRetries(t=>nr(t,e)),delete this.localCache[e],this.notifyServiceWorker(e)))}async _poll(){let e=await this._withRetries(e=>{let t=t7(e,!1).getAll();return new t8(t).toPromise()});if(!e||0!==this.pendingWrites)return[];let t=[],n=new Set;for(let{fbase_key:r,value:i}of e)n.add(r),JSON.stringify(this.localCache[r])!==JSON.stringify(i)&&(this.notifyListeners(r,i),t.push(r));for(let e of Object.keys(this.localCache))this.localCache[e]&&!n.has(e)&&(this.notifyListeners(e,null),t.push(e));return t}notifyListeners(e,t){this.localCache[e]=t;let n=this.listeners[e];if(n)for(let e of Array.from(n))e(t)}startPolling(){this.stopPolling(),this.pollTimer=setInterval(async()=>this._poll(),800)}stopPolling(){this.pollTimer&&(clearInterval(this.pollTimer),this.pollTimer=null)}_addListener(e,t){0===Object.keys(this.listeners).length&&this.startPolling(),this.listeners[e]||(this.listeners[e]=new Set,this._get(e)),this.listeners[e].add(t)}_removeListener(e,t){this.listeners[e]&&(this.listeners[e].delete(t),0===this.listeners[e].size&&delete this.listeners[e]),0===Object.keys(this.listeners).length&&this.stopPolling()}}ni.type="LOCAL";let ns=ni;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function na(e){return(await L(e,"GET","/v1/recaptchaParams")).recaptchaSiteKey||""}function no(e){return new Promise((t,n)=>{var r,i;let s=document.createElement("script");s.setAttribute("src",e),s.onload=t,s.onerror=e=>{let t=y("internal-error");t.customData=e,n(t)},s.type="text/javascript",s.charset="UTF-8",(null!==(i=null===(r=document.getElementsByTagName("head"))||void 0===r?void 0:r[0])&&void 0!==i?i:document).appendChild(s)})}function nl(e){return`__${e}${Math.floor(1e6*Math.random())}`}class nu{constructor(e){this.auth=e,this.counter=1e12,this._widgets=new Map}render(e,t){let n=this.counter;return this._widgets.set(n,new nc(e,this.auth.name,t||{})),this.counter++,n}reset(e){var t;let n=e||1e12;null===(t=this._widgets.get(n))||void 0===t||t.delete(),this._widgets.delete(n)}getResponse(e){var t;return(null===(t=this._widgets.get(e||1e12))||void 0===t?void 0:t.getResponse())||""}async execute(e){var t;return null===(t=this._widgets.get(e||1e12))||void 0===t||t.execute(),""}}class nc{constructor(e,t,n){this.params=n,this.timerId=null,this.deleted=!1,this.responseToken=null,this.clickHandler=()=>{this.execute()};let r="string"==typeof e?document.getElementById(e):e;b(r,"argument-error",{appName:t}),this.container=r,this.isVisible="invisible"!==this.params.size,this.isVisible?this.execute():this.container.addEventListener("click",this.clickHandler)}getResponse(){return this.checkIfDeleted(),this.responseToken}delete(){this.checkIfDeleted(),this.deleted=!0,this.timerId&&(clearTimeout(this.timerId),this.timerId=null),this.container.removeEventListener("click",this.clickHandler)}execute(){this.checkIfDeleted(),this.timerId||(this.timerId=window.setTimeout(()=>{this.responseToken=function(e){let t=[],n="1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";for(let e=0;e<50;e++)t.push(n.charAt(Math.floor(Math.random()*n.length)));return t.join("")}(0);let{callback:e,"expired-callback":t}=this.params;if(e)try{e(this.responseToken)}catch(e){}this.timerId=window.setTimeout(()=>{if(this.timerId=null,this.responseToken=null,t)try{t()}catch(e){}this.isVisible&&this.execute()},6e4)},500))}checkIfDeleted(){if(this.deleted)throw Error("reCAPTCHA mock was already deleted!")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nh=nl("rcb"),nd=new x(3e4,6e4);class nf{constructor(){var e;this.hostLanguage="",this.counter=0,this.librarySeparatelyLoaded=!!(null===(e=t2().grecaptcha)||void 0===e?void 0:e.render)}load(e,t=""){return(b(t.length<=6&&/^\s*[a-zA-Z0-9\-]*\s*$/.test(t),e,"argument-error"),this.shouldResolveImmediately(t))?Promise.resolve(t2().grecaptcha):new Promise((n,r)=>{let s=t2().setTimeout(()=>{r(y(e,"network-request-failed"))},nd.get());t2()[nh]=()=>{t2().clearTimeout(s),delete t2()[nh];let i=t2().grecaptcha;if(!i){r(y(e,"internal-error"));return}let a=i.render;i.render=(e,t)=>{let n=a(e,t);return this.counter++,n},this.hostLanguage=t,n(i)};let a=`https://www.google.com/recaptcha/api.js??${(0,i.xO)({onload:nh,render:"explicit",hl:t})}`;no(a).catch(()=>{clearTimeout(s),r(y(e,"internal-error"))})})}clearedOneInstance(){this.counter--}shouldResolveImmediately(e){var t;return!!(null===(t=t2().grecaptcha)||void 0===t?void 0:t.render)&&(e===this.hostLanguage||this.counter>0||this.librarySeparatelyLoaded)}}class np{async load(e){return new nu(e)}clearedOneInstance(){}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nm="recaptcha",ng={theme:"light",type:"image"};class ny{constructor(e,t=Object.assign({},ng),n){this.parameters=t,this.type=nm,this.destroyed=!1,this.widgetId=null,this.tokenChangeListeners=new Set,this.renderPromise=null,this.recaptcha=null,this.auth=eb(n),this.isInvisible="invisible"===this.parameters.size,b("undefined"!=typeof document,this.auth,"operation-not-supported-in-this-environment");let r="string"==typeof e?document.getElementById(e):e;b(r,this.auth,"argument-error"),this.container=r,this.parameters.callback=this.makeTokenCallback(this.parameters.callback),this._recaptchaLoader=this.auth.settings.appVerificationDisabledForTesting?new np:new nf,this.validateStartingState()}async verify(){this.assertNotDestroyed();let e=await this.render(),t=this.getAssertedRecaptcha(),n=t.getResponse(e);return n||new Promise(n=>{let r=e=>{e&&(this.tokenChangeListeners.delete(r),n(e))};this.tokenChangeListeners.add(r),this.isInvisible&&t.execute(e)})}render(){try{this.assertNotDestroyed()}catch(e){return Promise.reject(e)}return this.renderPromise||(this.renderPromise=this.makeRenderPromise().catch(e=>{throw this.renderPromise=null,e})),this.renderPromise}_reset(){this.assertNotDestroyed(),null!==this.widgetId&&this.getAssertedRecaptcha().reset(this.widgetId)}clear(){this.assertNotDestroyed(),this.destroyed=!0,this._recaptchaLoader.clearedOneInstance(),this.isInvisible||this.container.childNodes.forEach(e=>{this.container.removeChild(e)})}validateStartingState(){b(!this.parameters.sitekey,this.auth,"argument-error"),b(this.isInvisible||!this.container.hasChildNodes(),this.auth,"argument-error"),b("undefined"!=typeof document,this.auth,"operation-not-supported-in-this-environment")}makeTokenCallback(e){return t=>{if(this.tokenChangeListeners.forEach(e=>e(t)),"function"==typeof e)e(t);else if("string"==typeof e){let n=t2()[e];"function"==typeof n&&n(t)}}}assertNotDestroyed(){b(!this.destroyed,this.auth,"internal-error")}async makeRenderPromise(){if(await this.init(),!this.widgetId){let e=this.container;if(!this.isInvisible){let t=document.createElement("div");e.appendChild(t),e=t}this.widgetId=this.getAssertedRecaptcha().render(e,this.parameters)}return this.widgetId}async init(){let e;b(A()&&!t3(),this.auth,"internal-error"),await (e=null,new Promise(t=>{if("complete"===document.readyState){t();return}e=()=>t(),window.addEventListener("load",e)}).catch(t=>{throw e&&window.removeEventListener("load",e),t})),this.recaptcha=await this._recaptchaLoader.load(this.auth,this.auth.languageCode||void 0);let t=await na(this.auth);b(t,this.auth,"internal-error"),this.parameters.sitekey=t}getAssertedRecaptcha(){return b(this.recaptcha,this.auth,"internal-error"),this.recaptcha}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nv{constructor(e,t){this.verificationId=e,this.onConfirmation=t}confirm(e){let t=eK._fromVerification(this.verificationId,e);return this.onConfirmation(t)}}async function nw(e,t,n){let r=eb(e),s=await nI(r,t,(0,i.m9)(n));return new nv(s,e=>ta(r,e))}async function n_(e,t,n){let r=(0,i.m9)(e);await tr(!1,r,"phone");let s=await nI(r.auth,t,(0,i.m9)(n));return new nv(s,e=>to(r,e))}async function nb(e,t,n){let r=(0,i.m9)(e),s=await nI(r.auth,t,(0,i.m9)(n));return new nv(s,e=>tl(r,e))}async function nI(e,t,n){var r,i,s;let a=await n.verify();try{let o;if(b("string"==typeof a,e,"argument-error"),b(n.type===nm,e,"argument-error"),o="string"==typeof t?{phoneNumber:t}:t,"session"in o){let t=o.session;if("phoneNumber"in o){b("enroll"===t.type,e,"internal-error");let n=await (i={idToken:t.credential,phoneEnrollmentInfo:{phoneNumber:o.phoneNumber,recaptchaToken:a}},L(e,"POST","/v2/accounts/mfaEnrollment:start",P(e,i)));return n.phoneSessionInfo.sessionInfo}{b("signin"===t.type,e,"internal-error");let n=(null===(r=o.multiFactorHint)||void 0===r?void 0:r.uid)||o.multiFactorUid;b(n,e,"missing-multi-factor-info");let i=await (s={mfaPendingCredential:t.credential,mfaEnrollmentId:n,phoneSignInInfo:{recaptchaToken:a}},L(e,"POST","/v2/accounts/mfaSignIn:start",P(e,s)));return i.phoneResponseInfo.sessionInfo}}{let{sessionInfo:t}=await eB(e,{phoneNumber:o.phoneNumber,recaptchaToken:a});return t}}finally{n._reset()}}async function nT(e,t){await tn((0,i.m9)(e),t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nE{constructor(e){this.providerId=nE.PROVIDER_ID,this.auth=eb(e)}verifyPhoneNumber(e,t){return nI(this.auth,e,(0,i.m9)(t))}static credential(e,t){return eK._fromVerification(e,t)}static credentialFromResult(e){return nE.credentialFromTaggedObject(e)}static credentialFromError(e){return nE.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{phoneNumber:t,temporaryProof:n}=e;return t&&n?eK._fromTokenResponse(t,n):null}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function nS(e,t){return t?S(t):(b(e._popupRedirectResolver,e,"argument-error"),e._popupRedirectResolver)}nE.PROVIDER_ID="phone",nE.PHONE_SIGN_IN_METHOD="phone";/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nk extends ek{constructor(e){super("custom","custom"),this.params=e}_getIdTokenResponse(e){return eV(e,this._buildIdpRequest())}_linkToIdToken(e,t){return eV(e,this._buildIdpRequest(t))}_getReauthenticationResolver(e){return eV(e,this._buildIdpRequest())}_buildIdpRequest(e){let t={requestUri:this.params.requestUri,sessionId:this.params.sessionId,postBody:this.params.postBody,tenantId:this.params.tenantId,pendingToken:this.params.pendingToken,returnSecureToken:!0,returnIdpCredential:!0};return e&&(t.idToken=e),t}}function nA(e){return ts(e.auth,new nk(e),e.bypassAuthState)}function nC(e){let{auth:t,user:n}=e;return b(n,t,"internal-error"),ti(n,new nk(e),e.bypassAuthState)}async function nx(e){let{auth:t,user:n}=e;return b(n,t,"internal-error"),tn(n,new nk(e),e.bypassAuthState)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nN{constructor(e,t,n,r,i=!1){this.auth=e,this.resolver=n,this.user=r,this.bypassAuthState=i,this.pendingPromise=null,this.eventManager=null,this.filter=Array.isArray(t)?t:[t]}execute(){return new Promise(async(e,t)=>{this.pendingPromise={resolve:e,reject:t};try{this.eventManager=await this.resolver._initialize(this.auth),await this.onExecution(),this.eventManager.registerConsumer(this)}catch(e){this.reject(e)}})}async onAuthEvent(e){let{urlResponse:t,sessionId:n,postBody:r,tenantId:i,error:s,type:a}=e;if(s){this.reject(s);return}let o={auth:this.auth,requestUri:t,sessionId:n,tenantId:i||void 0,postBody:r||void 0,user:this.user,bypassAuthState:this.bypassAuthState};try{this.resolve(await this.getIdpTask(a)(o))}catch(e){this.reject(e)}}onError(e){this.reject(e)}getIdpTask(e){switch(e){case"signInViaPopup":case"signInViaRedirect":return nA;case"linkViaPopup":case"linkViaRedirect":return nx;case"reauthViaPopup":case"reauthViaRedirect":return nC;default:g(this.auth,"internal-error")}}resolve(e){T(this.pendingPromise,"Pending promise was never set"),this.pendingPromise.resolve(e),this.unregisterAndCleanUp()}reject(e){T(this.pendingPromise,"Pending promise was never set"),this.pendingPromise.reject(e),this.unregisterAndCleanUp()}unregisterAndCleanUp(){this.eventManager&&this.eventManager.unregisterConsumer(this),this.pendingPromise=null,this.cleanUp()}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nR=new x(2e3,1e4);async function nD(e,t,n){let r=eb(e);w(e,t,eQ);let i=nS(r,n),s=new nL(r,"signInViaPopup",t,i);return s.executeNotNull()}async function nO(e,t,n){let r=(0,i.m9)(e);w(r.auth,t,eQ);let s=nS(r.auth,n),a=new nL(r.auth,"reauthViaPopup",t,s,r);return a.executeNotNull()}async function nP(e,t,n){let r=(0,i.m9)(e);w(r.auth,t,eQ);let s=nS(r.auth,n),a=new nL(r.auth,"linkViaPopup",t,s,r);return a.executeNotNull()}class nL extends nN{constructor(e,t,n,r,i){super(e,t,r,i),this.provider=n,this.authWindow=null,this.pollId=null,nL.currentPopupAction&&nL.currentPopupAction.cancel(),nL.currentPopupAction=this}async executeNotNull(){let e=await this.execute();return b(e,this.auth,"internal-error"),e}async onExecution(){T(1===this.filter.length,"Popup operations only handle one event");let e=t0();this.authWindow=await this.resolver._openPopup(this.auth,this.provider,this.filter[0],e),this.authWindow.associatedEvent=e,this.resolver._originValidation(this.auth).catch(e=>{this.reject(e)}),this.resolver._isIframeWebStorageSupported(this.auth,e=>{e||this.reject(y(this.auth,"web-storage-unsupported"))}),this.pollUserCancellation()}get eventId(){var e;return(null===(e=this.authWindow)||void 0===e?void 0:e.associatedEvent)||null}cancel(){this.reject(y(this.auth,"cancelled-popup-request"))}cleanUp(){this.authWindow&&this.authWindow.close(),this.pollId&&window.clearTimeout(this.pollId),this.authWindow=null,this.pollId=null,nL.currentPopupAction=null}pollUserCancellation(){let e=()=>{var t,n;if(null===(n=null===(t=this.authWindow)||void 0===t?void 0:t.window)||void 0===n?void 0:n.closed){this.pollId=window.setTimeout(()=>{this.pollId=null,this.reject(y(this.auth,"popup-closed-by-user"))},2e3);return}this.pollId=window.setTimeout(e,nR.get())};e()}}nL.currentPopupAction=null;let nM=new Map;class nU extends nN{constructor(e,t,n=!1){super(e,["signInViaRedirect","linkViaRedirect","reauthViaRedirect","unknown"],t,void 0,n),this.eventId=null}async execute(){let e=nM.get(this.auth._key());if(!e){try{let t=await nF(this.resolver,this.auth),n=t?await super.execute():null;e=()=>Promise.resolve(n)}catch(t){e=()=>Promise.reject(t)}nM.set(this.auth._key(),e)}return this.bypassAuthState||nM.set(this.auth._key(),()=>Promise.resolve(null)),e()}async onAuthEvent(e){if("signInViaRedirect"===e.type)return super.onAuthEvent(e);if("unknown"===e.type){this.resolve(null);return}if(e.eventId){let t=await this.auth._redirectUserForId(e.eventId);if(t)return this.user=t,super.onAuthEvent(e);this.resolve(null)}}async onExecution(){}cleanUp(){}}async function nF(e,t){let n=nz(t),r=nj(e);if(!await r._isAvailable())return!1;let i=await r._get(n)==="true";return await r._remove(n),i}async function nV(e,t){return nj(e)._set(nz(t),"true")}function nq(){nM.clear()}function nB(e,t){nM.set(e._key(),t)}function nj(e){return S(e._redirectPersistence)}function nz(e){return es("pendingRedirect",e.config.apiKey,e.name)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function n$(e,t,n){return nG(e,t,n)}async function nG(e,t,n){let r=eb(e);w(e,t,eQ),await r._initializationPromise;let i=nS(r,n);return await nV(i,r),i._openRedirect(r,t,"signInViaRedirect")}function nK(e,t,n){return nW(e,t,n)}async function nW(e,t,n){let r=(0,i.m9)(e);w(r.auth,t,eQ),await r.auth._initializationPromise;let s=nS(r.auth,n);await nV(s,r.auth);let a=await nJ(r);return s._openRedirect(r.auth,t,"reauthViaRedirect",a)}function nH(e,t,n){return nQ(e,t,n)}async function nQ(e,t,n){let r=(0,i.m9)(e);w(r.auth,t,eQ),await r.auth._initializationPromise;let s=nS(r.auth,n);await tr(!1,r,t.providerId),await nV(s,r.auth);let a=await nJ(r);return s._openRedirect(r.auth,t,"linkViaRedirect",a)}async function nY(e,t){return await eb(e)._initializationPromise,nX(e,t,!1)}async function nX(e,t,n=!1){let r=eb(e),i=nS(r,t),s=new nU(r,i,n),a=await s.execute();return a&&!n&&(delete a.user._redirectEventId,await r._persistUserIfCurrent(a.user),await r._setRedirectUser(null,t)),a}async function nJ(e){let t=t0(`${e.uid}:::`);return e._redirectEventId=t,await e.auth._setRedirectUser(e),await e.auth._persistUserIfCurrent(e),t}class nZ{constructor(e){this.auth=e,this.cachedEventUids=new Set,this.consumers=new Set,this.queuedRedirectEvent=null,this.hasHandledPotentialRedirect=!1,this.lastProcessedEventTime=Date.now()}registerConsumer(e){this.consumers.add(e),this.queuedRedirectEvent&&this.isEventForConsumer(this.queuedRedirectEvent,e)&&(this.sendToConsumer(this.queuedRedirectEvent,e),this.saveEventToCache(this.queuedRedirectEvent),this.queuedRedirectEvent=null)}unregisterConsumer(e){this.consumers.delete(e)}onEvent(e){if(this.hasEventBeenHandled(e))return!1;let t=!1;return this.consumers.forEach(n=>{this.isEventForConsumer(e,n)&&(t=!0,this.sendToConsumer(e,n),this.saveEventToCache(e))}),this.hasHandledPotentialRedirect||!function(e){switch(e.type){case"signInViaRedirect":case"linkViaRedirect":case"reauthViaRedirect":return!0;case"unknown":return n1(e);default:return!1}}(e)||(this.hasHandledPotentialRedirect=!0,t||(this.queuedRedirectEvent=e,t=!0)),t}sendToConsumer(e,t){var n;if(e.error&&!n1(e)){let r=(null===(n=e.error.code)||void 0===n?void 0:n.split("auth/")[1])||"internal-error";t.onError(y(this.auth,r))}else t.onAuthEvent(e)}isEventForConsumer(e,t){let n=null===t.eventId||!!e.eventId&&e.eventId===t.eventId;return t.filter.includes(e.type)&&n}hasEventBeenHandled(e){return Date.now()-this.lastProcessedEventTime>=6e5&&this.cachedEventUids.clear(),this.cachedEventUids.has(n0(e))}saveEventToCache(e){this.cachedEventUids.add(n0(e)),this.lastProcessedEventTime=Date.now()}}function n0(e){return[e.type,e.eventId,e.sessionId,e.tenantId].filter(e=>e).join("-")}function n1({type:e,error:t}){return"unknown"===e&&(null==t?void 0:t.code)==="auth/no-auth-event"}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function n2(e,t={}){return L(e,"GET","/v1/projects",t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let n3=/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,n4=/^https?/;async function n6(e){if(e.config.emulator)return;let{authorizedDomains:t}=await n2(e);for(let e of t)try{if(function(e){let t=k(),{protocol:n,hostname:r}=new URL(t);if(e.startsWith("chrome-extension://")){let i=new URL(e);return""===i.hostname&&""===r?"chrome-extension:"===n&&e.replace("chrome-extension://","")===t.replace("chrome-extension://",""):"chrome-extension:"===n&&i.hostname===r}if(!n4.test(n))return!1;if(n3.test(e))return r===e;let i=e.replace(/\./g,"\\."),s=RegExp("^(.+\\."+i+"|"+i+")$","i");return s.test(r)}(e))return}catch(e){}g(e,"unauthorized-domain")}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let n5=new x(3e4,6e4);function n9(){let e=t2().___jsl;if(null==e?void 0:e.H){for(let t of Object.keys(e.H))if(e.H[t].r=e.H[t].r||[],e.H[t].L=e.H[t].L||[],e.H[t].r=[...e.H[t].L],e.CP)for(let t=0;t<e.CP.length;t++)e.CP[t]=null}}let n8=null,n7=new x(5e3,15e3),re={style:{position:"absolute",top:"-100px",width:"1px",height:"1px"},"aria-hidden":"true",tabindex:"-1"},rt=new Map([["identitytoolkit.googleapis.com","p"],["staging-identitytoolkit.sandbox.googleapis.com","s"],["test-identitytoolkit.sandbox.googleapis.com","t"]]);async function rn(e){let t=await (n8=n8||new Promise((t,n)=>{var r,i,s;function a(){n9(),gapi.load("gapi.iframes",{callback:()=>{t(gapi.iframes.getContext())},ontimeout:()=>{n9(),n(y(e,"network-request-failed"))},timeout:n5.get()})}if(null===(i=null===(r=t2().gapi)||void 0===r?void 0:r.iframes)||void 0===i?void 0:i.Iframe)t(gapi.iframes.getContext());else if(null===(s=t2().gapi)||void 0===s?void 0:s.load)a();else{let t=nl("iframefcb");return t2()[t]=()=>{gapi.load?a():n(y(e,"network-request-failed"))},no(`https://apis.google.com/js/api.js?onload=${t}`).catch(e=>n(e))}}).catch(e=>{throw n8=null,e})),n=t2().gapi;return b(n,e,"internal-error"),t.open({where:document.body,url:function(e){let t=e.config;b(t.authDomain,e,"auth-domain-config-required");let n=t.emulator?N(t,"emulator/auth/iframe"):`https://${e.config.authDomain}/__/auth/iframe`,r={apiKey:t.apiKey,appName:e.name,v:s.SDK_VERSION},a=rt.get(e.config.apiHost);a&&(r.eid=a);let o=e._getFrameworks();return o.length&&(r.fw=o.join(",")),`${n}?${(0,i.xO)(r).slice(1)}`}(e),messageHandlersFilter:n.iframes.CROSS_ORIGIN_IFRAMES_FILTER,attributes:re,dontclear:!0},t=>new Promise(async(n,r)=>{await t.restyle({setHideOnLeave:!1});let i=y(e,"network-request-failed"),s=t2().setTimeout(()=>{r(i)},n7.get());function a(){t2().clearTimeout(s),n(t)}t.ping(a).then(a,()=>{r(i)})}))}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let rr={location:"yes",resizable:"yes",statusbar:"yes",toolbar:"no"};class ri{constructor(e){this.window=e,this.associatedEvent=null}close(){if(this.window)try{this.window.close()}catch(e){}}}function rs(e,t,n,r,a,o){b(e.config.authDomain,e,"auth-domain-config-required"),b(e.config.apiKey,e,"invalid-api-key");let l={apiKey:e.config.apiKey,appName:e.name,authType:n,redirectUrl:r,v:s.SDK_VERSION,eventId:a};if(t instanceof eQ)for(let[n,r]of(t.setDefaultLanguage(e.languageCode),l.providerId=t.providerId||"",(0,i.xb)(t.getCustomParameters())||(l.customParameters=JSON.stringify(t.getCustomParameters())),Object.entries(o||{})))l[n]=r;if(t instanceof eY){let e=t.getScopes().filter(e=>""!==e);e.length>0&&(l.scopes=e.join(","))}e.tenantId&&(l.tid=e.tenantId);let u=l;for(let e of Object.keys(u))void 0===u[e]&&delete u[e];return`${function({config:e}){return e.emulator?N(e,"emulator/auth/handler"):`https://${e.authDomain}/__/auth/handler`}(e)}?${(0,i.xO)(u).slice(1)}`}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ra="webStorageSupport",ro=class{constructor(){this.eventManagers={},this.iframes={},this.originValidationPromises={},this._redirectPersistence=tJ,this._completeRedirectFn=nX,this._overrideRedirectResult=nB}async _openPopup(e,t,n,r){var s;T(null===(s=this.eventManagers[e._key()])||void 0===s?void 0:s.manager,"_initialize() not called before _openPopup()");let a=rs(e,t,n,k(),r);return function(e,t,n,r=500,s=600){let a=Math.max((window.screen.availHeight-s)/2,0).toString(),o=Math.max((window.screen.availWidth-r)/2,0).toString(),l="",u=Object.assign(Object.assign({},rr),{width:r.toString(),height:s.toString(),top:a,left:o}),c=(0,i.z$)().toLowerCase();n&&(l=ec(c)?"_blank":n),el(c)&&(t=t||"http://localhost",u.scrollbars="yes");let h=Object.entries(u).reduce((e,[t,n])=>`${e}${t}=${n},`,"");if(function(e=(0,i.z$)()){var t;return em(e)&&!!(null===(t=window.navigator)||void 0===t?void 0:t.standalone)}(c)&&"_self"!==l)return function(e,t){let n=document.createElement("a");n.href=e,n.target=t;let r=document.createEvent("MouseEvent");r.initMouseEvent("click",!0,!0,window,1,0,0,0,0,!1,!1,!1,!1,1,null),n.dispatchEvent(r)}(t||"",l),new ri(null);let d=window.open(t||"",l,h);b(d,e,"popup-blocked");try{d.focus()}catch(e){}return new ri(d)}(e,a,t0())}async _openRedirect(e,t,n,r){var i;return await this._originValidation(e),i=rs(e,t,n,k(),r),t2().location.href=i,new Promise(()=>{})}_initialize(e){let t=e._key();if(this.eventManagers[t]){let{manager:e,promise:n}=this.eventManagers[t];return e?Promise.resolve(e):(T(n,"If manager is not set, promise should be"),n)}let n=this.initAndGetManager(e);return this.eventManagers[t]={promise:n},n.catch(()=>{delete this.eventManagers[t]}),n}async initAndGetManager(e){let t=await rn(e),n=new nZ(e);return t.register("authEvent",t=>{b(null==t?void 0:t.authEvent,e,"invalid-auth-event");let r=n.onEvent(t.authEvent);return{status:r?"ACK":"ERROR"}},gapi.iframes.CROSS_ORIGIN_IFRAMES_FILTER),this.eventManagers[e._key()]={manager:n},this.iframes[e._key()]=t,n}_isIframeWebStorageSupported(e,t){let n=this.iframes[e._key()];n.send(ra,{type:ra},n=>{var r;let i=null===(r=null==n?void 0:n[0])||void 0===r?void 0:r[ra];void 0!==i&&t(!!i),g(e,"internal-error")},gapi.iframes.CROSS_ORIGIN_IFRAMES_FILTER)}_originValidation(e){let t=e._key();return this.originValidationPromises[t]||(this.originValidationPromises[t]=n6(e)),this.originValidationPromises[t]}get _shouldInitProactively(){return ey()||eu()||em()}};class rl{constructor(e){this.factorId=e}_process(e,t,n){switch(t.type){case"enroll":return this._finalizeEnroll(e,t.credential,n);case"signin":return this._finalizeSignIn(e,t.credential);default:return I("unexpected MultiFactorSessionType")}}}class ru extends rl{constructor(e){super("phone"),this.credential=e}static _fromCredential(e){return new ru(e)}_finalizeEnroll(e,t,n){return L(e,"POST","/v2/accounts/mfaEnrollment:finalize",P(e,{idToken:t,displayName:n,phoneVerificationInfo:this.credential._makeVerificationRequest()}))}_finalizeSignIn(e,t){return L(e,"POST","/v2/accounts/mfaSignIn:finalize",P(e,{mfaPendingCredential:t,phoneVerificationInfo:this.credential._makeVerificationRequest()}))}}class rc{constructor(){}static assertion(e){return ru._fromCredential(e)}}rc.FACTOR_ID="phone";var rh="@firebase/auth",rd="0.21.3";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rf{constructor(e){this.auth=e,this.internalListeners=new Map}getUid(){var e;return this.assertAuthConfigured(),(null===(e=this.auth.currentUser)||void 0===e?void 0:e.uid)||null}async getToken(e){if(this.assertAuthConfigured(),await this.auth._initializationPromise,!this.auth.currentUser)return null;let t=await this.auth.currentUser.getIdToken(e);return{accessToken:t}}addAuthTokenListener(e){if(this.assertAuthConfigured(),this.internalListeners.has(e))return;let t=this.auth.onIdTokenChanged(t=>{e((null==t?void 0:t.stsTokenManager.accessToken)||null)});this.internalListeners.set(e,t),this.updateProactiveRefresh()}removeAuthTokenListener(e){this.assertAuthConfigured();let t=this.internalListeners.get(e);t&&(this.internalListeners.delete(e),t(),this.updateProactiveRefresh())}assertAuthConfigured(){b(this.auth._initializationPromise,"dependent-sdk-initialized-before-auth")}updateProactiveRefresh(){this.internalListeners.size>0?this.auth._startProactiveRefresh():this.auth._stopProactiveRefresh()}}(0,i.Pz)("authIdTokenMaxAge"),r="Browser",(0,s._registerComponent)(new l.wA("auth",(e,{options:t})=>{let n=e.getProvider("app").getImmediate(),i=e.getProvider("heartbeat"),{apiKey:s,authDomain:a}=n.options;return((e,n)=>{b(s&&!s.includes(":"),"invalid-api-key",{appName:e.name}),b(!(null==a?void 0:a.includes(":")),"argument-error",{appName:e.name});let i={apiKey:s,authDomain:a,clientPlatform:r,apiHost:"identitytoolkit.googleapis.com",tokenApiHost:"securetoken.googleapis.com",apiScheme:"https",sdkClientVersion:ev(r)},o=new e_(e,n,i);return function(e,t){let n=(null==t?void 0:t.persistence)||[],r=(Array.isArray(n)?n:[n]).map(S);(null==t?void 0:t.errorMap)&&e._updateErrorMap(t.errorMap),e._initializeWithPersistence(r,null==t?void 0:t.popupRedirectResolver)}(o,t),o})(n,i)},"PUBLIC").setInstantiationMode("EXPLICIT").setInstanceCreatedCallback((e,t,n)=>{let r=e.getProvider("auth-internal");r.initialize()})),(0,s._registerComponent)(new l.wA("auth-internal",e=>{let t=eb(e.getProvider("auth").getImmediate());return new rf(t)},"PRIVATE").setInstantiationMode("EXPLICIT")),(0,s.registerVersion)(rh,rd,/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){switch(e){case"Node":return"node";case"ReactNative":return"rn";case"Worker":return"webworker";case"Cordova":return"cordova";default:return}}(r)),(0,s.registerVersion)(rh,rd,"esm2017")},1294:function(e,t,n){"use strict";n.d(t,{u7:function(){return hN},Jj:function(){return cF},IX:function(){return cE},my:function(){return u5},xU:function(){return hP},Lz:function(){return cV},WA:function(){return nQ},F8:function(){return cB},$q:function(){return hL},W:function(){return hM},EK:function(){return n8},PU:function(){return h0},l7:function(){return rR},Ky:function(){return ri},Xb:function(){return rr},Cf:function(){return u0},K9:function(){return nW},Me:function(){return rF},yq:function(){return n$},Wi:function(){return uY},ET:function(){return hH},Ab:function(){return h9},vr:function(){return h5},Fc:function(){return cR},hJ:function(){return u7},B$:function(){return ce},at:function(){return u6},oe:function(){return hW},AK:function(){return h4},TF:function(){return cP},JU:function(){return ct},ST:function(){return cC},fH:function(){return cx},Ix:function(){return cO},Wu:function(){return hE},Lx:function(){return hT},qY:function(){return ck},GL:function(){return hX},QT:function(){return hF},kl:function(){return hq},Xk:function(){return hB},PL:function(){return hj},UQ:function(){return hz},zN:function(){return h$},nP:function(){return h8},b9:function(){return hy},vh:function(){return hv},Pb:function(){return cL},L$:function(){return cM},cf:function(){return hQ},sc:function(){return hY},Xo:function(){return hm},IO:function(){return hc},iE:function(){return cr},Eo:function(){return cn},i3:function(){return h3},Bt:function(){return h6},pl:function(){return hG},Ub:function(){return nB},qK:function(){return hU},TQ:function(){return hb},e0:function(){return h_},r7:function(){return hK},Mx:function(){return cD},ar:function(){return hd}});var r,i,s,a,o,l,u,c,h=n(5816),d=n(8463),f=n(3333),p=n(4444),m="undefined"!=typeof globalThis?globalThis:"undefined"!=typeof window?window:void 0!==n.g?n.g:"undefined"!=typeof self?self:{},g={},y=y||{},v=m||self;function w(){}function _(e){var t=typeof e;return"array"==(t="object"!=t?t:e?Array.isArray(e)?"array":t:"null")||"object"==t&&"number"==typeof e.length}function b(e){var t=typeof e;return"object"==t&&null!=e||"function"==t}function I(e,t,n){return e.call.apply(e.bind,arguments)}function T(e,t,n){if(!e)throw Error();if(2<arguments.length){var r=Array.prototype.slice.call(arguments,2);return function(){var n=Array.prototype.slice.call(arguments);return Array.prototype.unshift.apply(n,r),e.apply(t,n)}}return function(){return e.apply(t,arguments)}}function E(e,t,n){return(E=Function.prototype.bind&&-1!=Function.prototype.bind.toString().indexOf("native code")?I:T).apply(null,arguments)}function S(e,t){var n=Array.prototype.slice.call(arguments,1);return function(){var t=n.slice();return t.push.apply(t,arguments),e.apply(this,t)}}function k(e,t){function n(){}n.prototype=t.prototype,e.X=t.prototype,e.prototype=new n,e.prototype.constructor=e,e.Wb=function(e,n,r){for(var i=Array(arguments.length-2),s=2;s<arguments.length;s++)i[s-2]=arguments[s];return t.prototype[n].apply(e,i)}}function A(){this.s=this.s,this.o=this.o}A.prototype.s=!1,A.prototype.na=function(){this.s||(this.s=!0,this.M())},A.prototype.M=function(){if(this.o)for(;this.o.length;)this.o.shift()()};let C=Array.prototype.indexOf?function(e,t){return Array.prototype.indexOf.call(e,t,void 0)}:function(e,t){if("string"==typeof e)return"string"!=typeof t||1!=t.length?-1:e.indexOf(t,0);for(let n=0;n<e.length;n++)if(n in e&&e[n]===t)return n;return -1};function x(e){let t=e.length;if(0<t){let n=Array(t);for(let r=0;r<t;r++)n[r]=e[r];return n}return[]}function N(e,t){for(let t=1;t<arguments.length;t++){let n=arguments[t];if(_(n)){let t=e.length||0,r=n.length||0;e.length=t+r;for(let i=0;i<r;i++)e[t+i]=n[i]}else e.push(n)}}function R(e,t){this.type=e,this.g=this.target=t,this.defaultPrevented=!1}R.prototype.h=function(){this.defaultPrevented=!0};var D=function(){if(!v.addEventListener||!Object.defineProperty)return!1;var e=!1,t=Object.defineProperty({},"passive",{get:function(){e=!0}});try{v.addEventListener("test",w,t),v.removeEventListener("test",w,t)}catch(e){}return e}();function O(e){return/^[\s\xa0]*$/.test(e)}var P=String.prototype.trim?function(e){return e.trim()}:function(e){return/^[\s\xa0]*([\s\S]*?)[\s\xa0]*$/.exec(e)[1]};function L(e,t){return e<t?-1:e>t?1:0}function M(){var e=v.navigator;return e&&(e=e.userAgent)?e:""}function U(e){return -1!=M().indexOf(e)}function F(e){return F[" "](e),e}F[" "]=w;var V=U("Opera"),q=U("Trident")||U("MSIE"),B=U("Edge"),j=B||q,z=U("Gecko")&&!(-1!=M().toLowerCase().indexOf("webkit")&&!U("Edge"))&&!(U("Trident")||U("MSIE"))&&!U("Edge"),$=-1!=M().toLowerCase().indexOf("webkit")&&!U("Edge");function G(){var e=v.document;return e?e.documentMode:void 0}e:{var K,W="",H=(K=M(),z?/rv:([^\);]+)(\)|;)/.exec(K):B?/Edge\/([\d\.]+)/.exec(K):q?/\b(?:MSIE|rv)[: ]([^\);]+)(\)|;)/.exec(K):$?/WebKit\/(\S+)/.exec(K):V?/(?:Version)[ \/]?(\S+)/.exec(K):void 0);if(H&&(W=H?H[1]:""),q){var Q=G();if(null!=Q&&Q>parseFloat(W)){i=String(Q);break e}}i=W}var Y={},X=v.document&&q&&(G()||parseInt(i,10))||void 0;function J(e,t){if(R.call(this,e?e.type:""),this.relatedTarget=this.g=this.target=null,this.button=this.screenY=this.screenX=this.clientY=this.clientX=0,this.key="",this.metaKey=this.shiftKey=this.altKey=this.ctrlKey=!1,this.state=null,this.pointerId=0,this.pointerType="",this.i=null,e){var n=this.type=e.type,r=e.changedTouches&&e.changedTouches.length?e.changedTouches[0]:null;if(this.target=e.target||e.srcElement,this.g=t,t=e.relatedTarget){if(z){e:{try{F(t.nodeName);var i=!0;break e}catch(e){}i=!1}i||(t=null)}}else"mouseover"==n?t=e.fromElement:"mouseout"==n&&(t=e.toElement);this.relatedTarget=t,r?(this.clientX=void 0!==r.clientX?r.clientX:r.pageX,this.clientY=void 0!==r.clientY?r.clientY:r.pageY,this.screenX=r.screenX||0,this.screenY=r.screenY||0):(this.clientX=void 0!==e.clientX?e.clientX:e.pageX,this.clientY=void 0!==e.clientY?e.clientY:e.pageY,this.screenX=e.screenX||0,this.screenY=e.screenY||0),this.button=e.button,this.key=e.key||"",this.ctrlKey=e.ctrlKey,this.altKey=e.altKey,this.shiftKey=e.shiftKey,this.metaKey=e.metaKey,this.pointerId=e.pointerId||0,this.pointerType="string"==typeof e.pointerType?e.pointerType:Z[e.pointerType]||"",this.state=e.state,this.i=e,e.defaultPrevented&&J.X.h.call(this)}}k(J,R);var Z={2:"touch",3:"pen",4:"mouse"};J.prototype.h=function(){J.X.h.call(this);var e=this.i;e.preventDefault?e.preventDefault():e.returnValue=!1};var ee="closure_listenable_"+(1e6*Math.random()|0),et=0;function en(e,t,n,r,i){this.listener=e,this.proxy=null,this.src=t,this.type=n,this.capture=!!r,this.ha=i,this.key=++et,this.ba=this.ea=!1}function er(e){e.ba=!0,e.listener=null,e.proxy=null,e.src=null,e.ha=null}function ei(e,t,n){for(let r in e)t.call(n,e[r],r,e)}function es(e){let t={};for(let n in e)t[n]=e[n];return t}let ea="constructor hasOwnProperty isPrototypeOf propertyIsEnumerable toLocaleString toString valueOf".split(" ");function eo(e,t){let n,r;for(let t=1;t<arguments.length;t++){for(n in r=arguments[t])e[n]=r[n];for(let t=0;t<ea.length;t++)n=ea[t],Object.prototype.hasOwnProperty.call(r,n)&&(e[n]=r[n])}}function el(e){this.src=e,this.g={},this.h=0}function eu(e,t){var n=t.type;if(n in e.g){var r,i=e.g[n],s=C(i,t);(r=0<=s)&&Array.prototype.splice.call(i,s,1),r&&(er(t),0==e.g[n].length&&(delete e.g[n],e.h--))}}function ec(e,t,n,r){for(var i=0;i<e.length;++i){var s=e[i];if(!s.ba&&s.listener==t&&!!n==s.capture&&s.ha==r)return i}return -1}el.prototype.add=function(e,t,n,r,i){var s=e.toString();(e=this.g[s])||(e=this.g[s]=[],this.h++);var a=ec(e,t,r,i);return -1<a?(t=e[a],n||(t.ea=!1)):((t=new en(t,this.src,s,!!r,i)).ea=n,e.push(t)),t};var eh="closure_lm_"+(1e6*Math.random()|0),ed={};function ef(e,t,n,r,i,s){if(!t)throw Error("Invalid event type");var a=b(i)?!!i.capture:!!i,o=ey(e);if(o||(e[eh]=o=new el(e)),(n=o.add(t,n,r,a,s)).proxy)return n;if(r=function e(t){return eg.call(e.src,e.listener,t)},n.proxy=r,r.src=e,r.listener=n,e.addEventListener)D||(i=a),void 0===i&&(i=!1),e.addEventListener(t.toString(),r,i);else if(e.attachEvent)e.attachEvent(em(t.toString()),r);else if(e.addListener&&e.removeListener)e.addListener(r);else throw Error("addEventListener and attachEvent are unavailable.");return n}function ep(e){if("number"!=typeof e&&e&&!e.ba){var t=e.src;if(t&&t[ee])eu(t.i,e);else{var n=e.type,r=e.proxy;t.removeEventListener?t.removeEventListener(n,r,e.capture):t.detachEvent?t.detachEvent(em(n),r):t.addListener&&t.removeListener&&t.removeListener(r),(n=ey(t))?(eu(n,e),0==n.h&&(n.src=null,t[eh]=null)):er(e)}}}function em(e){return e in ed?ed[e]:ed[e]="on"+e}function eg(e,t){if(e.ba)e=!0;else{t=new J(t,this);var n=e.listener,r=e.ha||e.src;e.ea&&ep(e),e=n.call(r,t)}return e}function ey(e){return(e=e[eh])instanceof el?e:null}var ev="__closure_events_fn_"+(1e9*Math.random()>>>0);function ew(e){return"function"==typeof e?e:(e[ev]||(e[ev]=function(t){return e.handleEvent(t)}),e[ev])}function e_(){A.call(this),this.i=new el(this),this.P=this,this.I=null}function eb(e,t){var n,r=e.I;if(r)for(n=[];r;r=r.I)n.push(r);if(e=e.P,r=t.type||t,"string"==typeof t)t=new R(t,e);else if(t instanceof R)t.target=t.target||e;else{var i=t;eo(t=new R(r,e),i)}if(i=!0,n)for(var s=n.length-1;0<=s;s--){var a=t.g=n[s];i=eI(a,r,!0,t)&&i}if(i=eI(a=t.g=e,r,!0,t)&&i,i=eI(a,r,!1,t)&&i,n)for(s=0;s<n.length;s++)i=eI(a=t.g=n[s],r,!1,t)&&i}function eI(e,t,n,r){if(!(t=e.i.g[String(t)]))return!0;t=t.concat();for(var i=!0,s=0;s<t.length;++s){var a=t[s];if(a&&!a.ba&&a.capture==n){var o=a.listener,l=a.ha||a.src;a.ea&&eu(e.i,a),i=!1!==o.call(l,r)&&i}}return i&&!r.defaultPrevented}k(e_,A),e_.prototype[ee]=!0,e_.prototype.removeEventListener=function(e,t,n,r){!function e(t,n,r,i,s){if(Array.isArray(n))for(var a=0;a<n.length;a++)e(t,n[a],r,i,s);else(i=b(i)?!!i.capture:!!i,r=ew(r),t&&t[ee])?(t=t.i,(n=String(n).toString())in t.g&&-1<(r=ec(a=t.g[n],r,i,s))&&(er(a[r]),Array.prototype.splice.call(a,r,1),0==a.length&&(delete t.g[n],t.h--))):t&&(t=ey(t))&&(n=t.g[n.toString()],t=-1,n&&(t=ec(n,r,i,s)),(r=-1<t?n[t]:null)&&ep(r))}(this,e,t,n,r)},e_.prototype.M=function(){if(e_.X.M.call(this),this.i){var e,t=this.i;for(e in t.g){for(var n=t.g[e],r=0;r<n.length;r++)er(n[r]);delete t.g[e],t.h--}}this.I=null},e_.prototype.N=function(e,t,n,r){return this.i.add(String(e),t,!1,n,r)},e_.prototype.O=function(e,t,n,r){return this.i.add(String(e),t,!0,n,r)};var eT=v.JSON.stringify,eE=new class{constructor(e,t){this.i=e,this.j=t,this.h=0,this.g=null}get(){let e;return 0<this.h?(this.h--,e=this.g,this.g=e.next,e.next=null):e=this.i(),e}}(()=>new eS,e=>e.reset());class eS{constructor(){this.next=this.g=this.h=null}set(e,t){this.h=e,this.g=t,this.next=null}reset(){this.next=this.g=this.h=null}}function ek(e,t){var n;a||(n=v.Promise.resolve(void 0),a=function(){n.then(ex)}),eA||(a(),eA=!0),eC.add(e,t)}var eA=!1,eC=new class{constructor(){this.h=this.g=null}add(e,t){let n=eE.get();n.set(e,t),this.h?this.h.next=n:this.g=n,this.h=n}};function ex(){let e;for(;e=null,(t=eC).g&&(e=t.g,t.g=t.g.next,t.g||(t.h=null),e.next=null),n=e;){try{n.h.call(n.g)}catch(e){!function(e){v.setTimeout(()=>{throw e},0)}(e)}var t,n,r=eE;r.j(n),100>r.h&&(r.h++,n.next=r.g,r.g=n)}eA=!1}function eN(e,t){e_.call(this),this.h=e||1,this.g=t||v,this.j=E(this.lb,this),this.l=Date.now()}function eR(e){e.ca=!1,e.R&&(e.g.clearTimeout(e.R),e.R=null)}function eD(e,t,n){if("function"==typeof e)n&&(e=E(e,n));else if(e&&"function"==typeof e.handleEvent)e=E(e.handleEvent,e);else throw Error("Invalid listener argument");return 2147483647<Number(t)?-1:v.setTimeout(e,t||0)}k(eN,e_),(c=eN.prototype).ca=!1,c.R=null,c.lb=function(){if(this.ca){var e=Date.now()-this.l;0<e&&e<.8*this.h?this.R=this.g.setTimeout(this.j,this.h-e):(this.R&&(this.g.clearTimeout(this.R),this.R=null),eb(this,"tick"),this.ca&&(eR(this),this.start()))}},c.start=function(){this.ca=!0,this.R||(this.R=this.g.setTimeout(this.j,this.h),this.l=Date.now())},c.M=function(){eN.X.M.call(this),eR(this),delete this.g};class eO extends A{constructor(e,t){super(),this.m=e,this.j=t,this.h=null,this.i=!1,this.g=null}l(e){this.h=arguments,this.g?this.i=!0:function e(t){t.g=eD(()=>{t.g=null,t.i&&(t.i=!1,e(t))},t.j);let n=t.h;t.h=null,t.m.apply(null,n)}(this)}M(){super.M(),this.g&&(v.clearTimeout(this.g),this.g=null,this.i=!1,this.h=null)}}function eP(e){A.call(this),this.h=e,this.g={}}k(eP,A);var eL=[];function eM(e,t,n,r){Array.isArray(n)||(n&&(eL[0]=n.toString()),n=eL);for(var i=0;i<n.length;i++){var s=function e(t,n,r,i,s){if(i&&i.once)return function e(t,n,r,i,s){if(Array.isArray(n)){for(var a=0;a<n.length;a++)e(t,n[a],r,i,s);return null}return r=ew(r),t&&t[ee]?t.O(n,r,b(i)?!!i.capture:!!i,s):ef(t,n,r,!0,i,s)}(t,n,r,i,s);if(Array.isArray(n)){for(var a=0;a<n.length;a++)e(t,n[a],r,i,s);return null}return r=ew(r),t&&t[ee]?t.N(n,r,b(i)?!!i.capture:!!i,s):ef(t,n,r,!1,i,s)}(t,n[i],r||e.handleEvent,!1,e.h||e);if(!s)break;e.g[s.key]=s}}function eU(e){ei(e.g,function(e,t){this.g.hasOwnProperty(t)&&ep(e)},e),e.g={}}function eF(){this.g=!0}function eV(e,t,n,r){e.info(function(){return"XMLHTTP TEXT ("+t+"): "+function(e,t){if(!e.g)return t;if(!t)return null;try{var n=JSON.parse(t);if(n){for(e=0;e<n.length;e++)if(Array.isArray(n[e])){var r=n[e];if(!(2>r.length)){var i=r[1];if(Array.isArray(i)&&!(1>i.length)){var s=i[0];if("noop"!=s&&"stop"!=s&&"close"!=s)for(var a=1;a<i.length;a++)i[a]=""}}}}return eT(n)}catch(e){return t}}(e,n)+(r?" "+r:"")})}eP.prototype.M=function(){eP.X.M.call(this),eU(this)},eP.prototype.handleEvent=function(){throw Error("EventHandler.handleEvent not implemented")},eF.prototype.Aa=function(){this.g=!1},eF.prototype.info=function(){};var eq={},eB=null;function ej(){return eB=eB||new e_}function ez(e){R.call(this,eq.Pa,e)}function e$(e){let t=ej();eb(t,new ez(t))}function eG(e,t){R.call(this,eq.STAT_EVENT,e),this.stat=t}function eK(e){let t=ej();eb(t,new eG(t,e))}function eW(e,t){R.call(this,eq.Qa,e),this.size=t}function eH(e,t){if("function"!=typeof e)throw Error("Fn must not be null and must be a function");return v.setTimeout(function(){e()},t)}eq.Pa="serverreachability",k(ez,R),eq.STAT_EVENT="statevent",k(eG,R),eq.Qa="timingevent",k(eW,R);var eQ={NO_ERROR:0,mb:1,zb:2,yb:3,tb:4,xb:5,Ab:6,Ma:7,TIMEOUT:8,Db:9},eY={rb:"complete",Nb:"success",Na:"error",Ma:"abort",Fb:"ready",Gb:"readystatechange",TIMEOUT:"timeout",Bb:"incrementaldata",Eb:"progress",ub:"downloadprogress",Vb:"uploadprogress"};function eX(){}function eJ(e){return e.h||(e.h=e.i())}function eZ(){}eX.prototype.h=null;var e0={OPEN:"a",qb:"b",Na:"c",Cb:"d"};function e1(){R.call(this,"d")}function e2(){R.call(this,"c")}function e3(){}function e4(e,t,n,r){this.l=e,this.j=t,this.m=n,this.U=r||1,this.S=new eP(this),this.O=e5,e=j?125:void 0,this.T=new eN(e),this.H=null,this.i=!1,this.s=this.A=this.v=this.K=this.F=this.V=this.B=null,this.D=[],this.g=null,this.C=0,this.o=this.u=null,this.Y=-1,this.I=!1,this.N=0,this.L=null,this.$=this.J=this.Z=this.P=!1,this.h=new e6}function e6(){this.i=null,this.g="",this.h=!1}k(e1,R),k(e2,R),k(e3,eX),e3.prototype.g=function(){return new XMLHttpRequest},e3.prototype.i=function(){return{}},o=new e3;var e5=45e3,e9={},e8={};function e7(e,t,n){e.K=1,e.v=ty(td(t)),e.s=n,e.P=!0,te(e,null)}function te(e,t){e.F=Date.now(),tr(e),e.A=td(e.v);var n=e.A,r=e.U;Array.isArray(r)||(r=[String(r)]),tN(n.i,"t",r),e.C=0,n=e.l.H,e.h=new e6,e.g=nw(e.l,n?t:null,!e.s),0<e.N&&(e.L=new eO(E(e.La,e,e.g),e.N)),eM(e.S,e.g,"readystatechange",e.ib),t=e.H?es(e.H):{},e.s?(e.u||(e.u="POST"),t["Content-Type"]="application/x-www-form-urlencoded",e.g.da(e.A,e.u,e.s,t)):(e.u="GET",e.g.da(e.A,e.u,null,t)),e$(),function(e,t,n,r,i,s){e.info(function(){if(e.g){if(s)for(var a="",o=s.split("&"),l=0;l<o.length;l++){var u=o[l].split("=");if(1<u.length){var c=u[0];u=u[1];var h=c.split("_");a=2<=h.length&&"type"==h[1]?a+(c+"=")+u+"&":a+(c+"=redacted&")}}else a=null}else a=s;return"XMLHTTP REQ ("+r+") [attempt "+i+"]: "+t+"\n"+n+"\n"+a})}(e.j,e.u,e.A,e.m,e.U,e.s)}function tt(e){return!!e.g&&"GET"==e.u&&2!=e.K&&e.l.Da}function tn(e,t,n){let r=!0,i;for(;!e.I&&e.C<n.length;)if((i=function(e,t){var n=e.C,r=t.indexOf("\n",n);return -1==r?e8:isNaN(n=Number(t.substring(n,r)))?e9:(r+=1)+n>t.length?e8:(t=t.substr(r,n),e.C=r+n,t)}(e,n))==e8){4==t&&(e.o=4,eK(14),r=!1),eV(e.j,e.m,null,"[Incomplete Response]");break}else if(i==e9){e.o=4,eK(15),eV(e.j,e.m,n,"[Invalid Chunk]"),r=!1;break}else eV(e.j,e.m,i,null),tl(e,i);tt(e)&&i!=e8&&i!=e9&&(e.h.g="",e.C=0),4!=t||0!=n.length||e.h.h||(e.o=1,eK(16),r=!1),e.i=e.i&&r,r?0<n.length&&!e.$&&(e.$=!0,(t=e.l).g==e&&t.$&&!t.K&&(t.j.info("Great, no buffering proxy detected. Bytes received: "+n.length),nh(t),t.K=!0,eK(11))):(eV(e.j,e.m,n,"[Invalid Chunked Response]"),to(e),ta(e))}function tr(e){e.V=Date.now()+e.O,ti(e,e.O)}function ti(e,t){if(null!=e.B)throw Error("WatchDog timer not null");e.B=eH(E(e.gb,e),t)}function ts(e){e.B&&(v.clearTimeout(e.B),e.B=null)}function ta(e){0==e.l.G||e.I||np(e.l,e)}function to(e){ts(e);var t=e.L;t&&"function"==typeof t.na&&t.na(),e.L=null,eR(e.T),eU(e.S),e.g&&(t=e.g,e.g=null,t.abort(),t.na())}function tl(e,t){try{var n=e.l;if(0!=n.G&&(n.g==e||tU(n.h,e))){if(!e.J&&tU(n.h,e)&&3==n.G){try{var r=n.Fa.g.parse(t)}catch(e){r=null}if(Array.isArray(r)&&3==r.length){var i=r;if(0==i[0]){e:if(!n.u){if(n.g){if(n.g.F+3e3<e.F)nf(n),nr(n);else break e}nc(n),eK(18)}}else n.Ba=i[1],0<n.Ba-n.T&&37500>i[2]&&n.L&&0==n.A&&!n.v&&(n.v=eH(E(n.cb,n),6e3));if(1>=tM(n.h)&&n.ja){try{n.ja()}catch(e){}n.ja=void 0}}else ng(n,11)}else if((e.J||n.g==e)&&nf(n),!O(t))for(i=n.Fa.g.parse(t),t=0;t<i.length;t++){let o=i[t];if(n.T=o[0],o=o[1],2==n.G){if("c"==o[0]){n.I=o[1],n.ka=o[2];let t=o[3];null!=t&&(n.ma=t,n.j.info("VER="+n.ma));let i=o[4];null!=i&&(n.Ca=i,n.j.info("SVER="+n.Ca));let l=o[5];null!=l&&"number"==typeof l&&0<l&&(r=1.5*l,n.J=r,n.j.info("backChannelRequestTimeoutMs_="+r)),r=n;let u=e.g;if(u){let e=u.g?u.g.getResponseHeader("X-Client-Wire-Protocol"):null;if(e){var s=r.h;s.g||-1==e.indexOf("spdy")&&-1==e.indexOf("quic")&&-1==e.indexOf("h2")||(s.j=s.l,s.g=new Set,s.h&&(tF(s,s.h),s.h=null))}if(r.D){let e=u.g?u.g.getResponseHeader("X-HTTP-Session-Id"):null;e&&(r.za=e,tg(r.F,r.D,e))}}if(n.G=3,n.l&&n.l.xa(),n.$&&(n.P=Date.now()-e.F,n.j.info("Handshake RTT: "+n.P+"ms")),(r=n).sa=nv(r,r.H?r.ka:null,r.V),e.J){tV(r.h,e);var a=r.J;a&&e.setTimeout(a),e.B&&(ts(e),tr(e)),r.g=e}else nu(r);0<n.i.length&&ns(n)}else"stop"!=o[0]&&"close"!=o[0]||ng(n,7)}else 3==n.G&&("stop"==o[0]||"close"==o[0]?"stop"==o[0]?ng(n,7):nn(n):"noop"!=o[0]&&n.l&&n.l.wa(o),n.A=0)}}e$(4)}catch(e){}}function tu(e,t){if(e.forEach&&"function"==typeof e.forEach)e.forEach(t,void 0);else if(_(e)||"string"==typeof e)Array.prototype.forEach.call(e,t,void 0);else for(var n=function(e){if(e.oa&&"function"==typeof e.oa)return e.oa();if(!e.W||"function"!=typeof e.W){if("undefined"!=typeof Map&&e instanceof Map)return Array.from(e.keys());if(!("undefined"!=typeof Set&&e instanceof Set)){if(_(e)||"string"==typeof e){var t=[];e=e.length;for(var n=0;n<e;n++)t.push(n);return t}for(let r in t=[],n=0,e)t[n++]=r;return t}}}(e),r=function(e){if(e.W&&"function"==typeof e.W)return e.W();if("undefined"!=typeof Map&&e instanceof Map||"undefined"!=typeof Set&&e instanceof Set)return Array.from(e.values());if("string"==typeof e)return e.split("");if(_(e)){for(var t=[],n=e.length,r=0;r<n;r++)t.push(e[r]);return t}for(r in t=[],n=0,e)t[n++]=e[r];return t}(e),i=r.length,s=0;s<i;s++)t.call(void 0,r[s],n&&n[s],e)}(c=e4.prototype).setTimeout=function(e){this.O=e},c.ib=function(e){e=e.target;let t=this.L;t&&3==t5(e)?t.l():this.La(e)},c.La=function(e){try{if(e==this.g)e:{let c=t5(this.g);var t=this.g.Ea();let h=this.g.aa();if(!(3>c)&&(3!=c||j||this.g&&(this.h.h||this.g.fa()||t9(this.g)))){this.I||4!=c||7==t||(8==t||0>=h?e$(3):e$(2)),ts(this);var n=this.g.aa();this.Y=n;t:if(tt(this)){var r=t9(this.g);e="";var i=r.length,s=4==t5(this.g);if(!this.h.i){if("undefined"==typeof TextDecoder){to(this),ta(this);var a="";break t}this.h.i=new v.TextDecoder}for(t=0;t<i;t++)this.h.h=!0,e+=this.h.i.decode(r[t],{stream:s&&t==i-1});r.splice(0,i),this.h.g+=e,this.C=0,a=this.h.g}else a=this.g.fa();if(this.i=200==n,function(e,t,n,r,i,s,a){e.info(function(){return"XMLHTTP RESP ("+r+") [ attempt "+i+"]: "+t+"\n"+n+"\n"+s+" "+a})}(this.j,this.u,this.A,this.m,this.U,c,n),this.i){if(this.Z&&!this.J){t:{if(this.g){var o,l=this.g;if((o=l.g?l.g.getResponseHeader("X-HTTP-Initial-Response"):null)&&!O(o)){var u=o;break t}}u=null}if(n=u)eV(this.j,this.m,n,"Initial handshake response via X-HTTP-Initial-Response"),this.J=!0,tl(this,n);else{this.i=!1,this.o=3,eK(12),to(this),ta(this);break e}}this.P?(tn(this,c,a),j&&this.i&&3==c&&(eM(this.S,this.T,"tick",this.hb),this.T.start())):(eV(this.j,this.m,a,null),tl(this,a)),4==c&&to(this),this.i&&!this.I&&(4==c?np(this.l,this):(this.i=!1,tr(this)))}else 400==n&&0<a.indexOf("Unknown SID")?(this.o=3,eK(12)):(this.o=0,eK(13)),to(this),ta(this)}}}catch(e){}finally{}},c.hb=function(){if(this.g){var e=t5(this.g),t=this.g.fa();this.C<t.length&&(ts(this),tn(this,e,t),this.i&&4!=e&&tr(this))}},c.cancel=function(){this.I=!0,to(this)},c.gb=function(){this.B=null;let e=Date.now();0<=e-this.V?(function(e,t){e.info(function(){return"TIMEOUT: "+t})}(this.j,this.A),2!=this.K&&(e$(),eK(17)),to(this),this.o=2,ta(this)):ti(this,this.V-e)};var tc=RegExp("^(?:([^:/?#.]+):)?(?://(?:([^\\\\/?#]*)@)?([^\\\\/?#]*?)(?::([0-9]+))?(?=[\\\\/?#]|$))?([^?#]+)?(?:\\?([^#]*))?(?:#([\\s\\S]*))?$");function th(e,t){if(this.g=this.s=this.j="",this.m=null,this.o=this.l="",this.h=!1,e instanceof th){this.h=void 0!==t?t:e.h,tf(this,e.j),this.s=e.s,this.g=e.g,tp(this,e.m),this.l=e.l,t=e.i;var n=new tk;n.i=t.i,t.g&&(n.g=new Map(t.g),n.h=t.h),tm(this,n),this.o=e.o}else e&&(n=String(e).match(tc))?(this.h=!!t,tf(this,n[1]||"",!0),this.s=tv(n[2]||""),this.g=tv(n[3]||"",!0),tp(this,n[4]),this.l=tv(n[5]||"",!0),tm(this,n[6]||"",!0),this.o=tv(n[7]||"")):(this.h=!!t,this.i=new tk(null,this.h))}function td(e){return new th(e)}function tf(e,t,n){e.j=n?tv(t,!0):t,e.j&&(e.j=e.j.replace(/:$/,""))}function tp(e,t){if(t){if(isNaN(t=Number(t))||0>t)throw Error("Bad port number "+t);e.m=t}else e.m=null}function tm(e,t,n){var r,i;t instanceof tk?(e.i=t,r=e.i,(i=e.h)&&!r.j&&(tA(r),r.i=null,r.g.forEach(function(e,t){var n=t.toLowerCase();t!=n&&(tC(this,t),tN(this,n,e))},r)),r.j=i):(n||(t=tw(t,tE)),e.i=new tk(t,e.h))}function tg(e,t,n){e.i.set(t,n)}function ty(e){return tg(e,"zx",Math.floor(2147483648*Math.random()).toString(36)+Math.abs(Math.floor(2147483648*Math.random())^Date.now()).toString(36)),e}function tv(e,t){return e?t?decodeURI(e.replace(/%25/g,"%2525")):decodeURIComponent(e):""}function tw(e,t,n){return"string"==typeof e?(e=encodeURI(e).replace(t,t_),n&&(e=e.replace(/%25([0-9a-fA-F]{2})/g,"%$1")),e):null}function t_(e){return"%"+((e=e.charCodeAt(0))>>4&15).toString(16)+(15&e).toString(16)}th.prototype.toString=function(){var e=[],t=this.j;t&&e.push(tw(t,tb,!0),":");var n=this.g;return(n||"file"==t)&&(e.push("//"),(t=this.s)&&e.push(tw(t,tb,!0),"@"),e.push(encodeURIComponent(String(n)).replace(/%25([0-9a-fA-F]{2})/g,"%$1")),null!=(n=this.m)&&e.push(":",String(n))),(n=this.l)&&(this.g&&"/"!=n.charAt(0)&&e.push("/"),e.push(tw(n,"/"==n.charAt(0)?tT:tI,!0))),(n=this.i.toString())&&e.push("?",n),(n=this.o)&&e.push("#",tw(n,tS)),e.join("")};var tb=/[#\/\?@]/g,tI=/[#\?:]/g,tT=/[#\?]/g,tE=/[#\?@]/g,tS=/#/g;function tk(e,t){this.h=this.g=null,this.i=e||null,this.j=!!t}function tA(e){e.g||(e.g=new Map,e.h=0,e.i&&function(e,t){if(e){e=e.split("&");for(var n=0;n<e.length;n++){var r=e[n].indexOf("="),i=null;if(0<=r){var s=e[n].substring(0,r);i=e[n].substring(r+1)}else s=e[n];t(s,i?decodeURIComponent(i.replace(/\+/g," ")):"")}}}(e.i,function(t,n){e.add(decodeURIComponent(t.replace(/\+/g," ")),n)}))}function tC(e,t){tA(e),t=tR(e,t),e.g.has(t)&&(e.i=null,e.h-=e.g.get(t).length,e.g.delete(t))}function tx(e,t){return tA(e),t=tR(e,t),e.g.has(t)}function tN(e,t,n){tC(e,t),0<n.length&&(e.i=null,e.g.set(tR(e,t),x(n)),e.h+=n.length)}function tR(e,t){return t=String(t),e.j&&(t=t.toLowerCase()),t}(c=tk.prototype).add=function(e,t){tA(this),this.i=null,e=tR(this,e);var n=this.g.get(e);return n||this.g.set(e,n=[]),n.push(t),this.h+=1,this},c.forEach=function(e,t){tA(this),this.g.forEach(function(n,r){n.forEach(function(n){e.call(t,n,r,this)},this)},this)},c.oa=function(){tA(this);let e=Array.from(this.g.values()),t=Array.from(this.g.keys()),n=[];for(let r=0;r<t.length;r++){let i=e[r];for(let e=0;e<i.length;e++)n.push(t[r])}return n},c.W=function(e){tA(this);let t=[];if("string"==typeof e)tx(this,e)&&(t=t.concat(this.g.get(tR(this,e))));else{e=Array.from(this.g.values());for(let n=0;n<e.length;n++)t=t.concat(e[n])}return t},c.set=function(e,t){return tA(this),this.i=null,tx(this,e=tR(this,e))&&(this.h-=this.g.get(e).length),this.g.set(e,[t]),this.h+=1,this},c.get=function(e,t){return e&&0<(e=this.W(e)).length?String(e[0]):t},c.toString=function(){if(this.i)return this.i;if(!this.g)return"";let e=[],t=Array.from(this.g.keys());for(var n=0;n<t.length;n++){var r=t[n];let s=encodeURIComponent(String(r)),a=this.W(r);for(r=0;r<a.length;r++){var i=s;""!==a[r]&&(i+="="+encodeURIComponent(String(a[r]))),e.push(i)}}return this.i=e.join("&")};var tD=class{constructor(e,t){this.h=e,this.g=t}};function tO(e){this.l=e||tP,e=v.PerformanceNavigationTiming?0<(e=v.performance.getEntriesByType("navigation")).length&&("hq"==e[0].nextHopProtocol||"h2"==e[0].nextHopProtocol):!!(v.g&&v.g.Ga&&v.g.Ga()&&v.g.Ga().$b),this.j=e?this.l:1,this.g=null,1<this.j&&(this.g=new Set),this.h=null,this.i=[]}var tP=10;function tL(e){return!!e.h||!!e.g&&e.g.size>=e.j}function tM(e){return e.h?1:e.g?e.g.size:0}function tU(e,t){return e.h?e.h==t:!!e.g&&e.g.has(t)}function tF(e,t){e.g?e.g.add(t):e.h=t}function tV(e,t){e.h&&e.h==t?e.h=null:e.g&&e.g.has(t)&&e.g.delete(t)}function tq(e){if(null!=e.h)return e.i.concat(e.h.D);if(null!=e.g&&0!==e.g.size){let t=e.i;for(let n of e.g.values())t=t.concat(n.D);return t}return x(e.i)}function tB(){}function tj(){this.g=new tB}function tz(e,t,n,r,i){try{t.onload=null,t.onerror=null,t.onabort=null,t.ontimeout=null,i(r)}catch(e){}}function t$(e){this.l=e.ac||null,this.j=e.jb||!1}function tG(e,t){e_.call(this),this.D=e,this.u=t,this.m=void 0,this.readyState=tK,this.status=0,this.responseType=this.responseText=this.response=this.statusText="",this.onreadystatechange=null,this.v=new Headers,this.h=null,this.C="GET",this.B="",this.g=!1,this.A=this.j=this.l=null}tO.prototype.cancel=function(){if(this.i=tq(this),this.h)this.h.cancel(),this.h=null;else if(this.g&&0!==this.g.size){for(let e of this.g.values())e.cancel();this.g.clear()}},tB.prototype.stringify=function(e){return v.JSON.stringify(e,void 0)},tB.prototype.parse=function(e){return v.JSON.parse(e,void 0)},k(t$,eX),t$.prototype.g=function(){return new tG(this.l,this.j)},t$.prototype.i=(r={},function(){return r}),k(tG,e_);var tK=0;function tW(e){e.j.read().then(e.Ta.bind(e)).catch(e.ga.bind(e))}function tH(e){e.readyState=4,e.l=null,e.j=null,e.A=null,tQ(e)}function tQ(e){e.onreadystatechange&&e.onreadystatechange.call(e)}(c=tG.prototype).open=function(e,t){if(this.readyState!=tK)throw this.abort(),Error("Error reopening a connection");this.C=e,this.B=t,this.readyState=1,tQ(this)},c.send=function(e){if(1!=this.readyState)throw this.abort(),Error("need to call open() first. ");this.g=!0;let t={headers:this.v,method:this.C,credentials:this.m,cache:void 0};e&&(t.body=e),(this.D||v).fetch(new Request(this.B,t)).then(this.Wa.bind(this),this.ga.bind(this))},c.abort=function(){this.response=this.responseText="",this.v=new Headers,this.status=0,this.j&&this.j.cancel("Request was aborted.").catch(()=>{}),1<=this.readyState&&this.g&&4!=this.readyState&&(this.g=!1,tH(this)),this.readyState=tK},c.Wa=function(e){if(this.g&&(this.l=e,this.h||(this.status=this.l.status,this.statusText=this.l.statusText,this.h=e.headers,this.readyState=2,tQ(this)),this.g&&(this.readyState=3,tQ(this),this.g))){if("arraybuffer"===this.responseType)e.arrayBuffer().then(this.Ua.bind(this),this.ga.bind(this));else if(void 0!==v.ReadableStream&&"body"in e){if(this.j=e.body.getReader(),this.u){if(this.responseType)throw Error('responseType must be empty for "streamBinaryChunks" mode responses.');this.response=[]}else this.response=this.responseText="",this.A=new TextDecoder;tW(this)}else e.text().then(this.Va.bind(this),this.ga.bind(this))}},c.Ta=function(e){if(this.g){if(this.u&&e.value)this.response.push(e.value);else if(!this.u){var t=e.value?e.value:new Uint8Array(0);(t=this.A.decode(t,{stream:!e.done}))&&(this.response=this.responseText+=t)}e.done?tH(this):tQ(this),3==this.readyState&&tW(this)}},c.Va=function(e){this.g&&(this.response=this.responseText=e,tH(this))},c.Ua=function(e){this.g&&(this.response=e,tH(this))},c.ga=function(){this.g&&tH(this)},c.setRequestHeader=function(e,t){this.v.append(e,t)},c.getResponseHeader=function(e){return this.h&&this.h.get(e.toLowerCase())||""},c.getAllResponseHeaders=function(){if(!this.h)return"";let e=[],t=this.h.entries();for(var n=t.next();!n.done;)e.push((n=n.value)[0]+": "+n[1]),n=t.next();return e.join("\r\n")},Object.defineProperty(tG.prototype,"withCredentials",{get:function(){return"include"===this.m},set:function(e){this.m=e?"include":"same-origin"}});var tY=v.JSON.parse;function tX(e){e_.call(this),this.headers=new Map,this.u=e||null,this.h=!1,this.C=this.g=null,this.H="",this.m=0,this.j="",this.l=this.F=this.v=this.D=!1,this.B=0,this.A=null,this.J=tJ,this.K=this.L=!1}k(tX,e_);var tJ="",tZ=/^https?$/i,t0=["POST","PUT"];function t1(e,t){e.h=!1,e.g&&(e.l=!0,e.g.abort(),e.l=!1),e.j=t,e.m=5,t2(e),t4(e)}function t2(e){e.D||(e.D=!0,eb(e,"complete"),eb(e,"error"))}function t3(e){if(e.h&&void 0!==y&&(!e.C[1]||4!=t5(e)||2!=e.aa())){if(e.v&&4==t5(e))eD(e.Ha,0,e);else if(eb(e,"readystatechange"),4==t5(e)){e.h=!1;try{let o=e.aa();e:switch(o){case 200:case 201:case 202:case 204:case 206:case 304:case 1223:var t,n,r=!0;break e;default:r=!1}if(!(t=r)){if(n=0===o){var i=String(e.H).match(tc)[1]||null;if(!i&&v.self&&v.self.location){var s=v.self.location.protocol;i=s.substr(0,s.length-1)}n=!tZ.test(i?i.toLowerCase():"")}t=n}if(t)eb(e,"complete"),eb(e,"success");else{e.m=6;try{var a=2<t5(e)?e.g.statusText:""}catch(e){a=""}e.j=a+" ["+e.aa()+"]",t2(e)}}finally{t4(e)}}}}function t4(e,t){if(e.g){t6(e);let n=e.g,r=e.C[0]?w:null;e.g=null,e.C=null,t||eb(e,"ready");try{n.onreadystatechange=r}catch(e){}}}function t6(e){e.g&&e.K&&(e.g.ontimeout=null),e.A&&(v.clearTimeout(e.A),e.A=null)}function t5(e){return e.g?e.g.readyState:0}function t9(e){try{if(!e.g)return null;if("response"in e.g)return e.g.response;switch(e.J){case tJ:case"text":return e.g.responseText;case"arraybuffer":if("mozResponseArrayBuffer"in e.g)return e.g.mozResponseArrayBuffer}return null}catch(e){return null}}function t8(e){let t="";return ei(e,function(e,n){t+=n+":"+e+"\r\n"}),t}function t7(e,t,n){e:{for(r in n){var r=!1;break e}r=!0}r||(n=t8(n),"string"==typeof e?null!=n&&encodeURIComponent(String(n)):tg(e,t,n))}function ne(e,t,n){return n&&n.internalChannelParams&&n.internalChannelParams[e]||t}function nt(e){this.Ca=0,this.i=[],this.j=new eF,this.ka=this.sa=this.F=this.V=this.g=this.za=this.D=this.ia=this.o=this.S=this.s=null,this.ab=this.U=0,this.Za=ne("failFast",!1,e),this.L=this.v=this.u=this.m=this.l=null,this.Y=!0,this.pa=this.Ba=this.T=-1,this.Z=this.A=this.C=0,this.Xa=ne("baseRetryDelayMs",5e3,e),this.bb=ne("retryDelaySeedMs",1e4,e),this.$a=ne("forwardChannelMaxRetries",2,e),this.ta=ne("forwardChannelRequestTimeoutMs",2e4,e),this.ra=e&&e.xmlHttpFactory||void 0,this.Da=e&&e.Zb||!1,this.J=void 0,this.H=e&&e.supportsCrossDomainXhr||!1,this.I="",this.h=new tO(e&&e.concurrentRequestLimit),this.Fa=new tj,this.O=e&&e.fastHandshake||!1,this.N=e&&e.encodeInitMessageHeaders||!1,this.O&&this.N&&(this.N=!1),this.Ya=e&&e.Xb||!1,e&&e.Aa&&this.j.Aa(),e&&e.forceLongPolling&&(this.Y=!1),this.$=!this.O&&this.Y&&e&&e.detectBufferingProxy||!1,this.ja=void 0,this.P=0,this.K=!1,this.la=this.B=null}function nn(e){if(ni(e),3==e.G){var t=e.U++,n=td(e.F);tg(n,"SID",e.I),tg(n,"RID",t),tg(n,"TYPE","terminate"),no(e,n),(t=new e4(e,e.j,t,void 0)).K=2,t.v=ty(td(n)),n=!1,v.navigator&&v.navigator.sendBeacon&&(n=v.navigator.sendBeacon(t.v.toString(),"")),!n&&v.Image&&((new Image).src=t.v,n=!0),n||(t.g=nw(t.l,null),t.g.da(t.v)),t.F=Date.now(),tr(t)}ny(e)}function nr(e){e.g&&(nh(e),e.g.cancel(),e.g=null)}function ni(e){nr(e),e.u&&(v.clearTimeout(e.u),e.u=null),nf(e),e.h.cancel(),e.m&&("number"==typeof e.m&&v.clearTimeout(e.m),e.m=null)}function ns(e){tL(e.h)||e.m||(e.m=!0,ek(e.Ja,e),e.C=0)}function na(e,t){var n;n=t?t.m:e.U++;let r=td(e.F);tg(r,"SID",e.I),tg(r,"RID",n),tg(r,"AID",e.T),no(e,r),e.o&&e.s&&t7(r,e.o,e.s),n=new e4(e,e.j,n,e.C+1),null===e.o&&(n.H=e.s),t&&(e.i=t.D.concat(e.i)),t=nl(e,n,1e3),n.setTimeout(Math.round(.5*e.ta)+Math.round(.5*e.ta*Math.random())),tF(e.h,n),e7(n,r,t)}function no(e,t){e.ia&&ei(e.ia,function(e,n){tg(t,n,e)}),e.l&&tu({},function(e,n){tg(t,n,e)})}function nl(e,t,n){n=Math.min(e.i.length,n);var r=e.l?E(e.l.Ra,e.l,e):null;e:{var i=e.i;let t=-1;for(;;){let e=["count="+n];-1==t?0<n?(t=i[0].h,e.push("ofs="+t)):t=0:e.push("ofs="+t);let s=!0;for(let a=0;a<n;a++){let n=i[a].h,o=i[a].g;if(0>(n-=t))t=Math.max(0,i[a].h-100),s=!1;else try{!function(e,t,n){let r=n||"";try{tu(e,function(e,n){let i=e;b(e)&&(i=eT(e)),t.push(r+n+"="+encodeURIComponent(i))})}catch(e){throw t.push(r+"type="+encodeURIComponent("_badmap")),e}}(o,e,"req"+n+"_")}catch(e){r&&r(o)}}if(s){r=e.join("&");break e}}}return e=e.i.splice(0,n),t.D=e,r}function nu(e){e.g||e.u||(e.Z=1,ek(e.Ia,e),e.A=0)}function nc(e){return!e.g&&!e.u&&!(3<=e.A)&&(e.Z++,e.u=eH(E(e.Ia,e),nm(e,e.A)),e.A++,!0)}function nh(e){null!=e.B&&(v.clearTimeout(e.B),e.B=null)}function nd(e){e.g=new e4(e,e.j,"rpc",e.Z),null===e.o&&(e.g.H=e.s),e.g.N=0;var t=td(e.sa);tg(t,"RID","rpc"),tg(t,"SID",e.I),tg(t,"CI",e.L?"0":"1"),tg(t,"AID",e.T),tg(t,"TYPE","xmlhttp"),no(e,t),e.o&&e.s&&t7(t,e.o,e.s),e.J&&e.g.setTimeout(e.J);var n=e.g;e=e.ka,n.K=1,n.v=ty(td(t)),n.s=null,n.P=!0,te(n,e)}function nf(e){null!=e.v&&(v.clearTimeout(e.v),e.v=null)}function np(e,t){var n=null;if(e.g==t){nf(e),nh(e),e.g=null;var r=2}else{if(!tU(e.h,t))return;n=t.D,tV(e.h,t),r=1}if(0!=e.G){if(e.pa=t.Y,t.i){if(1==r){n=t.s?t.s.length:0,t=Date.now()-t.F;var i,s,a=e.C;eb(r=ej(),new eW(r,n)),ns(e)}else nu(e)}else if(3==(a=t.o)||0==a&&0<e.pa||!(1==r&&(i=e,s=t,!(tM(i.h)>=i.h.j-(i.m?1:0))&&(i.m?(i.i=s.D.concat(i.i),!0):1!=i.G&&2!=i.G&&!(i.C>=(i.Za?0:i.$a))&&(i.m=eH(E(i.Ja,i,s),nm(i,i.C)),i.C++,!0)))||2==r&&nc(e)))switch(n&&0<n.length&&((t=e.h).i=t.i.concat(n)),a){case 1:ng(e,5);break;case 4:ng(e,10);break;case 3:ng(e,6);break;default:ng(e,2)}}}function nm(e,t){let n=e.Xa+Math.floor(Math.random()*e.bb);return e.l||(n*=2),n*t}function ng(e,t){if(e.j.info("Error code "+t),2==t){var n=null;e.l&&(n=null);var r=E(e.kb,e);n||(n=new th("//www.google.com/images/cleardot.gif"),v.location&&"http"==v.location.protocol||tf(n,"https"),ty(n)),function(e,t){let n=new eF;if(v.Image){let r=new Image;r.onload=S(tz,n,r,"TestLoadImage: loaded",!0,t),r.onerror=S(tz,n,r,"TestLoadImage: error",!1,t),r.onabort=S(tz,n,r,"TestLoadImage: abort",!1,t),r.ontimeout=S(tz,n,r,"TestLoadImage: timeout",!1,t),v.setTimeout(function(){r.ontimeout&&r.ontimeout()},1e4),r.src=e}else t(!1)}(n.toString(),r)}else eK(2);e.G=0,e.l&&e.l.va(t),ny(e),ni(e)}function ny(e){if(e.G=0,e.la=[],e.l){let t=tq(e.h);(0!=t.length||0!=e.i.length)&&(N(e.la,t),N(e.la,e.i),e.h.i.length=0,x(e.i),e.i.length=0),e.l.ua()}}function nv(e,t,n){var r=n instanceof th?td(n):new th(n,void 0);if(""!=r.g)t&&(r.g=t+"."+r.g),tp(r,r.m);else{var i=v.location;r=i.protocol,t=t?t+"."+i.hostname:i.hostname,i=+i.port;var s=new th(null,void 0);r&&tf(s,r),t&&(s.g=t),i&&tp(s,i),n&&(s.l=n),r=s}return n=e.D,t=e.za,n&&t&&tg(r,n,t),tg(r,"VER",e.ma),no(e,r),r}function nw(e,t,n){if(t&&!e.H)throw Error("Can't create secondary domain capable XhrIo object.");return(t=new tX(n&&e.Da&&!e.ra?new t$({jb:!0}):e.ra)).Ka(e.H),t}function n_(){}function nb(){if(q&&!(10<=Number(X)))throw Error("Environmental error: no available transport.")}function nI(e,t){e_.call(this),this.g=new nt(t),this.l=e,this.h=t&&t.messageUrlParams||null,e=t&&t.messageHeaders||null,t&&t.clientProtocolHeaderRequired&&(e?e["X-Client-Protocol"]="webchannel":e={"X-Client-Protocol":"webchannel"}),this.g.s=e,e=t&&t.initMessageHeaders||null,t&&t.messageContentType&&(e?e["X-WebChannel-Content-Type"]=t.messageContentType:e={"X-WebChannel-Content-Type":t.messageContentType}),t&&t.ya&&(e?e["X-WebChannel-Client-Profile"]=t.ya:e={"X-WebChannel-Client-Profile":t.ya}),this.g.S=e,(e=t&&t.Yb)&&!O(e)&&(this.g.o=e),this.A=t&&t.supportsCrossDomainXhr||!1,this.v=t&&t.sendRawJson||!1,(t=t&&t.httpSessionIdParam)&&!O(t)&&(this.g.D=t,null!==(e=this.h)&&t in e&&t in(e=this.h)&&delete e[t]),this.j=new nS(this)}function nT(e){e1.call(this);var t=e.__sm__;if(t){e:{for(let n in t){e=n;break e}e=void 0}(this.i=e)&&(e=this.i,t=null!==t&&e in t?t[e]:void 0),this.data=t}else this.data=e}function nE(){e2.call(this),this.status=1}function nS(e){this.g=e}(c=tX.prototype).Ka=function(e){this.L=e},c.da=function(e,t,n,r){if(this.g)throw Error("[goog.net.XhrIo] Object is active with another request="+this.H+"; newUri="+e);t=t?t.toUpperCase():"GET",this.H=e,this.j="",this.m=0,this.D=!1,this.h=!0,this.g=this.u?this.u.g():o.g(),this.C=this.u?eJ(this.u):eJ(o),this.g.onreadystatechange=E(this.Ha,this);try{this.F=!0,this.g.open(t,String(e),!0),this.F=!1}catch(e){t1(this,e);return}if(e=n||"",n=new Map(this.headers),r){if(Object.getPrototypeOf(r)===Object.prototype)for(var s in r)n.set(s,r[s]);else if("function"==typeof r.keys&&"function"==typeof r.get)for(let e of r.keys())n.set(e,r.get(e));else throw Error("Unknown input type for opt_headers: "+String(r))}for(let[i,a]of(r=Array.from(n.keys()).find(e=>"content-type"==e.toLowerCase()),s=v.FormData&&e instanceof v.FormData,!(0<=C(t0,t))||r||s||n.set("Content-Type","application/x-www-form-urlencoded;charset=utf-8"),n))this.g.setRequestHeader(i,a);this.J&&(this.g.responseType=this.J),"withCredentials"in this.g&&this.g.withCredentials!==this.L&&(this.g.withCredentials=this.L);try{var a,l;t6(this),0<this.B&&((this.K=(a=this.g,q&&(l=Y,Object.prototype.hasOwnProperty.call(l,9)?l[9]:l[9]=function(){let e=0,t=P(String(i)).split("."),n=P("9").split("."),r=Math.max(t.length,n.length);for(let i=0;0==e&&i<r;i++){var s=t[i]||"",a=n[i]||"";do{if(s=/(\d*)(\D*)(.*)/.exec(s)||["","","",""],a=/(\d*)(\D*)(.*)/.exec(a)||["","","",""],0==s[0].length&&0==a[0].length)break;e=L(0==s[1].length?0:parseInt(s[1],10),0==a[1].length?0:parseInt(a[1],10))||L(0==s[2].length,0==a[2].length)||L(s[2],a[2]),s=s[3],a=a[3]}while(0==e)}return 0<=e}(9))&&"number"==typeof a.timeout&&void 0!==a.ontimeout))?(this.g.timeout=this.B,this.g.ontimeout=E(this.qa,this)):this.A=eD(this.qa,this.B,this)),this.v=!0,this.g.send(e),this.v=!1}catch(e){t1(this,e)}},c.qa=function(){void 0!==y&&this.g&&(this.j="Timed out after "+this.B+"ms, aborting",this.m=8,eb(this,"timeout"),this.abort(8))},c.abort=function(e){this.g&&this.h&&(this.h=!1,this.l=!0,this.g.abort(),this.l=!1,this.m=e||7,eb(this,"complete"),eb(this,"abort"),t4(this))},c.M=function(){this.g&&(this.h&&(this.h=!1,this.l=!0,this.g.abort(),this.l=!1),t4(this,!0)),tX.X.M.call(this)},c.Ha=function(){this.s||(this.F||this.v||this.l?t3(this):this.fb())},c.fb=function(){t3(this)},c.aa=function(){try{return 2<t5(this)?this.g.status:-1}catch(e){return -1}},c.fa=function(){try{return this.g?this.g.responseText:""}catch(e){return""}},c.Sa=function(e){if(this.g){var t=this.g.responseText;return e&&0==t.indexOf(e)&&(t=t.substring(e.length)),tY(t)}},c.Ea=function(){return this.m},c.Oa=function(){return"string"==typeof this.j?this.j:String(this.j)},(c=nt.prototype).ma=8,c.G=1,c.Ja=function(e){if(this.m){if(this.m=null,1==this.G){if(!e){this.U=Math.floor(1e5*Math.random()),e=this.U++;let i=new e4(this,this.j,e,void 0),s=this.s;if(this.S&&(s?eo(s=es(s),this.S):s=this.S),null!==this.o||this.N||(i.H=s,s=null),this.O)e:{for(var t=0,n=0;n<this.i.length;n++){t:{var r=this.i[n];if("__data__"in r.g&&"string"==typeof(r=r.g.__data__)){r=r.length;break t}r=void 0}if(void 0===r)break;if(4096<(t+=r)){t=n;break e}if(4096===t||n===this.i.length-1){t=n+1;break e}}t=1e3}else t=1e3;t=nl(this,i,t),tg(n=td(this.F),"RID",e),tg(n,"CVER",22),this.D&&tg(n,"X-HTTP-Session-Id",this.D),no(this,n),s&&(this.N?t="headers="+encodeURIComponent(String(t8(s)))+"&"+t:this.o&&t7(n,this.o,s)),tF(this.h,i),this.Ya&&tg(n,"TYPE","init"),this.O?(tg(n,"$req",t),tg(n,"SID","null"),i.Z=!0,e7(i,n,null)):e7(i,n,t),this.G=2}}else 3==this.G&&(e?na(this,e):0==this.i.length||tL(this.h)||na(this))}},c.Ia=function(){if(this.u=null,nd(this),this.$&&!(this.K||null==this.g||0>=this.P)){var e=2*this.P;this.j.info("BP detection timer enabled: "+e),this.B=eH(E(this.eb,this),e)}},c.eb=function(){this.B&&(this.B=null,this.j.info("BP detection timeout reached."),this.j.info("Buffering proxy detected and switch to long-polling!"),this.L=!1,this.K=!0,eK(10),nr(this),nd(this))},c.cb=function(){null!=this.v&&(this.v=null,nr(this),nc(this),eK(19))},c.kb=function(e){e?(this.j.info("Successfully pinged google.com"),eK(2)):(this.j.info("Failed to ping google.com"),eK(1))},(c=n_.prototype).xa=function(){},c.wa=function(){},c.va=function(){},c.ua=function(){},c.Ra=function(){},nb.prototype.g=function(e,t){return new nI(e,t)},k(nI,e_),nI.prototype.m=function(){this.g.l=this.j,this.A&&(this.g.H=!0);var e=this.g,t=this.l,n=this.h||void 0;eK(0),e.V=t,e.ia=n||{},e.L=e.Y,e.F=nv(e,null,e.V),ns(e)},nI.prototype.close=function(){nn(this.g)},nI.prototype.u=function(e){var t=this.g;if("string"==typeof e){var n={};n.__data__=e,e=n}else this.v&&((n={}).__data__=eT(e),e=n);t.i.push(new tD(t.ab++,e)),3==t.G&&ns(t)},nI.prototype.M=function(){this.g.l=null,delete this.j,nn(this.g),delete this.g,nI.X.M.call(this)},k(nT,e1),k(nE,e2),k(nS,n_),nS.prototype.xa=function(){eb(this.g,"a")},nS.prototype.wa=function(e){eb(this.g,new nT(e))},nS.prototype.va=function(e){eb(this.g,new nE)},nS.prototype.ua=function(){eb(this.g,"b")},nb.prototype.createWebChannel=nb.prototype.g,nI.prototype.send=nI.prototype.u,nI.prototype.open=nI.prototype.m,nI.prototype.close=nI.prototype.close,eQ.NO_ERROR=0,eQ.TIMEOUT=8,eQ.HTTP_ERROR=6,eY.COMPLETE="complete",eZ.EventType=e0,e0.OPEN="a",e0.CLOSE="b",e0.ERROR="c",e0.MESSAGE="d",e_.prototype.listen=e_.prototype.N,tX.prototype.listenOnce=tX.prototype.O,tX.prototype.getLastError=tX.prototype.Oa,tX.prototype.getLastErrorCode=tX.prototype.Ea,tX.prototype.getStatus=tX.prototype.aa,tX.prototype.getResponseJson=tX.prototype.Sa,tX.prototype.getResponseText=tX.prototype.fa,tX.prototype.send=tX.prototype.da,tX.prototype.setWithCredentials=tX.prototype.Ka;var nk=g.createWebChannelTransport=function(){return new nb},nA=g.getStatEventTarget=function(){return ej()},nC=g.ErrorCode=eQ,nx=g.EventType=eY,nN=g.Event=eq,nR=g.Stat={sb:0,vb:1,wb:2,Pb:3,Ub:4,Rb:5,Sb:6,Qb:7,Ob:8,Tb:9,PROXY:10,NOPROXY:11,Mb:12,Ib:13,Jb:14,Hb:15,Kb:16,Lb:17,ob:18,nb:19,pb:20},nD=g.FetchXmlHttpFactory=t$,nO=g.WebChannel=eZ,nP=g.XhrIo=tX,nL=n(3454);let nM="@firebase/firestore";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nU{constructor(e){this.uid=e}isAuthenticated(){return null!=this.uid}toKey(){return this.isAuthenticated()?"uid:"+this.uid:"anonymous-user"}isEqual(e){return e.uid===this.uid}}nU.UNAUTHENTICATED=new nU(null),nU.GOOGLE_CREDENTIALS=new nU("google-credentials-uid"),nU.FIRST_PARTY=new nU("first-party-uid"),nU.MOCK_USER=new nU("mock-user");/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nF="9.17.1",nV=new f.Yd("@firebase/firestore");function nq(){return nV.logLevel}function nB(e){nV.setLogLevel(e)}function nj(e,...t){if(nV.logLevel<=f.in.DEBUG){let n=t.map(nG);nV.debug(`Firestore (${nF}): ${e}`,...n)}}function nz(e,...t){if(nV.logLevel<=f.in.ERROR){let n=t.map(nG);nV.error(`Firestore (${nF}): ${e}`,...n)}}function n$(e,...t){if(nV.logLevel<=f.in.WARN){let n=t.map(nG);nV.warn(`Firestore (${nF}): ${e}`,...n)}}function nG(e){if("string"==typeof e)return e;try{return JSON.stringify(e)}catch(t){return e}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function nK(e="Unexpected state"){let t=`FIRESTORE (${nF}) INTERNAL ASSERTION FAILED: `+e;throw nz(t),Error(t)}function nW(e,t){e||nK()}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nH={OK:"ok",CANCELLED:"cancelled",UNKNOWN:"unknown",INVALID_ARGUMENT:"invalid-argument",DEADLINE_EXCEEDED:"deadline-exceeded",NOT_FOUND:"not-found",ALREADY_EXISTS:"already-exists",PERMISSION_DENIED:"permission-denied",UNAUTHENTICATED:"unauthenticated",RESOURCE_EXHAUSTED:"resource-exhausted",FAILED_PRECONDITION:"failed-precondition",ABORTED:"aborted",OUT_OF_RANGE:"out-of-range",UNIMPLEMENTED:"unimplemented",INTERNAL:"internal",UNAVAILABLE:"unavailable",DATA_LOSS:"data-loss"};class nQ extends p.ZR{constructor(e,t){super(e,t),this.code=e,this.message=t,this.toString=()=>`${this.name}: [code=${this.code}]: ${this.message}`}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nY{constructor(){this.promise=new Promise((e,t)=>{this.resolve=e,this.reject=t})}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nX{constructor(e,t){this.user=t,this.type="OAuth",this.headers=new Map,this.headers.set("Authorization",`Bearer ${e}`)}}class nJ{getToken(){return Promise.resolve(null)}invalidateToken(){}start(e,t){e.enqueueRetryable(()=>t(nU.UNAUTHENTICATED))}shutdown(){}}class nZ{constructor(e){this.token=e,this.changeListener=null}getToken(){return Promise.resolve(this.token)}invalidateToken(){}start(e,t){this.changeListener=t,e.enqueueRetryable(()=>t(this.token.user))}shutdown(){this.changeListener=null}}class n0{constructor(e){this.t=e,this.currentUser=nU.UNAUTHENTICATED,this.i=0,this.forceRefresh=!1,this.auth=null}start(e,t){let n=this.i,r=e=>this.i!==n?(n=this.i,t(e)):Promise.resolve(),i=new nY;this.o=()=>{this.i++,this.currentUser=this.u(),i.resolve(),i=new nY,e.enqueueRetryable(()=>r(this.currentUser))};let s=()=>{let t=i;e.enqueueRetryable(async()=>{await t.promise,await r(this.currentUser)})},a=e=>{nj("FirebaseAuthCredentialsProvider","Auth detected"),this.auth=e,this.auth.addAuthTokenListener(this.o),s()};this.t.onInit(e=>a(e)),setTimeout(()=>{if(!this.auth){let e=this.t.getImmediate({optional:!0});e?a(e):(nj("FirebaseAuthCredentialsProvider","Auth not yet detected"),i.resolve(),i=new nY)}},0),s()}getToken(){let e=this.i,t=this.forceRefresh;return this.forceRefresh=!1,this.auth?this.auth.getToken(t).then(t=>this.i!==e?(nj("FirebaseAuthCredentialsProvider","getToken aborted due to token change."),this.getToken()):t?("string"==typeof t.accessToken||nK(),new nX(t.accessToken,this.currentUser)):null):Promise.resolve(null)}invalidateToken(){this.forceRefresh=!0}shutdown(){this.auth&&this.auth.removeAuthTokenListener(this.o)}u(){let e=this.auth&&this.auth.getUid();return null===e||"string"==typeof e||nK(),new nU(e)}}class n1{constructor(e,t,n,r){this.h=e,this.l=t,this.m=n,this.g=r,this.type="FirstParty",this.user=nU.FIRST_PARTY,this.p=new Map}I(){return this.g?this.g():("object"==typeof this.h&&null!==this.h&&this.h.auth&&this.h.auth.getAuthHeaderValueForFirstParty||nK(),this.h.auth.getAuthHeaderValueForFirstParty([]))}get headers(){this.p.set("X-Goog-AuthUser",this.l);let e=this.I();return e&&this.p.set("Authorization",e),this.m&&this.p.set("X-Goog-Iam-Authorization-Token",this.m),this.p}}class n2{constructor(e,t,n,r){this.h=e,this.l=t,this.m=n,this.g=r}getToken(){return Promise.resolve(new n1(this.h,this.l,this.m,this.g))}start(e,t){e.enqueueRetryable(()=>t(nU.FIRST_PARTY))}shutdown(){}invalidateToken(){}}class n3{constructor(e){this.value=e,this.type="AppCheck",this.headers=new Map,e&&e.length>0&&this.headers.set("x-firebase-appcheck",this.value)}}class n4{constructor(e){this.T=e,this.forceRefresh=!1,this.appCheck=null,this.A=null}start(e,t){let n=e=>{null!=e.error&&nj("FirebaseAppCheckTokenProvider",`Error getting App Check token; using placeholder token instead. Error: ${e.error.message}`);let n=e.token!==this.A;return this.A=e.token,nj("FirebaseAppCheckTokenProvider",`Received ${n?"new":"existing"} token.`),n?t(e.token):Promise.resolve()};this.o=t=>{e.enqueueRetryable(()=>n(t))};let r=e=>{nj("FirebaseAppCheckTokenProvider","AppCheck detected"),this.appCheck=e,this.appCheck.addTokenListener(this.o)};this.T.onInit(e=>r(e)),setTimeout(()=>{if(!this.appCheck){let e=this.T.getImmediate({optional:!0});e?r(e):nj("FirebaseAppCheckTokenProvider","AppCheck not yet detected")}},0)}getToken(){let e=this.forceRefresh;return this.forceRefresh=!1,this.appCheck?this.appCheck.getToken(e).then(e=>e?("string"==typeof e.token||nK(),this.A=e.token,new n3(e.token)):null):Promise.resolve(null)}invalidateToken(){this.forceRefresh=!0}shutdown(){this.appCheck&&this.appCheck.removeTokenListener(this.o)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class n6{static R(){let e="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",t=Math.floor(256/e.length)*e.length,n="";for(;n.length<20;){let r=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){let t="undefined"!=typeof self&&(self.crypto||self.msCrypto),n=new Uint8Array(e);if(t&&"function"==typeof t.getRandomValues)t.getRandomValues(n);else for(let t=0;t<e;t++)n[t]=Math.floor(256*Math.random());return n}(40);for(let i=0;i<r.length;++i)n.length<20&&r[i]<t&&(n+=e.charAt(r[i]%e.length))}return n}}function n5(e,t){return e<t?-1:e>t?1:0}function n9(e,t,n){return e.length===t.length&&e.every((e,r)=>n(e,t[r]))}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class n8{constructor(e,t){if(this.seconds=e,this.nanoseconds=t,t<0||t>=1e9)throw new nQ(nH.INVALID_ARGUMENT,"Timestamp nanoseconds out of range: "+t);if(e<-62135596800||e>=253402300800)throw new nQ(nH.INVALID_ARGUMENT,"Timestamp seconds out of range: "+e)}static now(){return n8.fromMillis(Date.now())}static fromDate(e){return n8.fromMillis(e.getTime())}static fromMillis(e){let t=Math.floor(e/1e3);return new n8(t,Math.floor(1e6*(e-1e3*t)))}toDate(){return new Date(this.toMillis())}toMillis(){return 1e3*this.seconds+this.nanoseconds/1e6}_compareTo(e){return this.seconds===e.seconds?n5(this.nanoseconds,e.nanoseconds):n5(this.seconds,e.seconds)}isEqual(e){return e.seconds===this.seconds&&e.nanoseconds===this.nanoseconds}toString(){return"Timestamp(seconds="+this.seconds+", nanoseconds="+this.nanoseconds+")"}toJSON(){return{seconds:this.seconds,nanoseconds:this.nanoseconds}}valueOf(){let e=this.seconds- -62135596800;return String(e).padStart(12,"0")+"."+String(this.nanoseconds).padStart(9,"0")}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class n7{constructor(e){this.timestamp=e}static fromTimestamp(e){return new n7(e)}static min(){return new n7(new n8(0,0))}static max(){return new n7(new n8(253402300799,999999999))}compareTo(e){return this.timestamp._compareTo(e.timestamp)}isEqual(e){return this.timestamp.isEqual(e.timestamp)}toMicroseconds(){return 1e6*this.timestamp.seconds+this.timestamp.nanoseconds/1e3}toString(){return"SnapshotVersion("+this.timestamp.toString()+")"}toTimestamp(){return this.timestamp}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class re{constructor(e,t,n){void 0===t?t=0:t>e.length&&nK(),void 0===n?n=e.length-t:n>e.length-t&&nK(),this.segments=e,this.offset=t,this.len=n}get length(){return this.len}isEqual(e){return 0===re.comparator(this,e)}child(e){let t=this.segments.slice(this.offset,this.limit());return e instanceof re?e.forEach(e=>{t.push(e)}):t.push(e),this.construct(t)}limit(){return this.offset+this.length}popFirst(e){return e=void 0===e?1:e,this.construct(this.segments,this.offset+e,this.length-e)}popLast(){return this.construct(this.segments,this.offset,this.length-1)}firstSegment(){return this.segments[this.offset]}lastSegment(){return this.get(this.length-1)}get(e){return this.segments[this.offset+e]}isEmpty(){return 0===this.length}isPrefixOf(e){if(e.length<this.length)return!1;for(let t=0;t<this.length;t++)if(this.get(t)!==e.get(t))return!1;return!0}isImmediateParentOf(e){if(this.length+1!==e.length)return!1;for(let t=0;t<this.length;t++)if(this.get(t)!==e.get(t))return!1;return!0}forEach(e){for(let t=this.offset,n=this.limit();t<n;t++)e(this.segments[t])}toArray(){return this.segments.slice(this.offset,this.limit())}static comparator(e,t){let n=Math.min(e.length,t.length);for(let r=0;r<n;r++){let n=e.get(r),i=t.get(r);if(n<i)return -1;if(n>i)return 1}return e.length<t.length?-1:e.length>t.length?1:0}}class rt extends re{construct(e,t,n){return new rt(e,t,n)}canonicalString(){return this.toArray().join("/")}toString(){return this.canonicalString()}static fromString(...e){let t=[];for(let n of e){if(n.indexOf("//")>=0)throw new nQ(nH.INVALID_ARGUMENT,`Invalid segment (${n}). Paths must not contain // in them.`);t.push(...n.split("/").filter(e=>e.length>0))}return new rt(t)}static emptyPath(){return new rt([])}}let rn=/^[_a-zA-Z][_a-zA-Z0-9]*$/;class rr extends re{construct(e,t,n){return new rr(e,t,n)}static isValidIdentifier(e){return rn.test(e)}canonicalString(){return this.toArray().map(e=>(e=e.replace(/\\/g,"\\\\").replace(/`/g,"\\`"),rr.isValidIdentifier(e)||(e="`"+e+"`"),e)).join(".")}toString(){return this.canonicalString()}isKeyField(){return 1===this.length&&"__name__"===this.get(0)}static keyField(){return new rr(["__name__"])}static fromServerFormat(e){let t=[],n="",r=0,i=()=>{if(0===n.length)throw new nQ(nH.INVALID_ARGUMENT,`Invalid field path (${e}). Paths must not be empty, begin with '.', end with '.', or contain '..'`);t.push(n),n=""},s=!1;for(;r<e.length;){let t=e[r];if("\\"===t){if(r+1===e.length)throw new nQ(nH.INVALID_ARGUMENT,"Path has trailing escape character: "+e);let t=e[r+1];if("\\"!==t&&"."!==t&&"`"!==t)throw new nQ(nH.INVALID_ARGUMENT,"Path has invalid escape sequence: "+e);n+=t,r+=2}else"`"===t?(s=!s,r++):"."!==t||s?(n+=t,r++):(i(),r++)}if(i(),s)throw new nQ(nH.INVALID_ARGUMENT,"Unterminated ` in path: "+e);return new rr(t)}static emptyPath(){return new rr([])}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ri{constructor(e){this.path=e}static fromPath(e){return new ri(rt.fromString(e))}static fromName(e){return new ri(rt.fromString(e).popFirst(5))}static empty(){return new ri(rt.emptyPath())}get collectionGroup(){return this.path.popLast().lastSegment()}hasCollectionId(e){return this.path.length>=2&&this.path.get(this.path.length-2)===e}getCollectionGroup(){return this.path.get(this.path.length-2)}getCollectionPath(){return this.path.popLast()}isEqual(e){return null!==e&&0===rt.comparator(this.path,e.path)}toString(){return this.path.toString()}static comparator(e,t){return rt.comparator(e.path,t.path)}static isDocumentKey(e){return e.length%2==0}static fromSegments(e){return new ri(new rt(e.slice()))}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rs{constructor(e,t,n,r){this.indexId=e,this.collectionGroup=t,this.fields=n,this.indexState=r}}function ra(e){return e.fields.find(e=>2===e.kind)}function ro(e){return e.fields.filter(e=>2!==e.kind)}rs.UNKNOWN_ID=-1;class rl{constructor(e,t){this.fieldPath=e,this.kind=t}}class ru{constructor(e,t){this.sequenceNumber=e,this.offset=t}static empty(){return new ru(0,rd.min())}}function rc(e,t){let n=e.toTimestamp().seconds,r=e.toTimestamp().nanoseconds+1,i=n7.fromTimestamp(1e9===r?new n8(n+1,0):new n8(n,r));return new rd(i,ri.empty(),t)}function rh(e){return new rd(e.readTime,e.key,-1)}class rd{constructor(e,t,n){this.readTime=e,this.documentKey=t,this.largestBatchId=n}static min(){return new rd(n7.min(),ri.empty(),-1)}static max(){return new rd(n7.max(),ri.empty(),-1)}}function rf(e,t){let n=e.readTime.compareTo(t.readTime);return 0!==n?n:0!==(n=ri.comparator(e.documentKey,t.documentKey))?n:n5(e.largestBatchId,t.largestBatchId)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let rp="The current tab is not in the required state to perform this operation. It might be necessary to refresh the browser tab.";class rm{constructor(){this.onCommittedListeners=[]}addOnCommittedListener(e){this.onCommittedListeners.push(e)}raiseOnCommittedEvent(){this.onCommittedListeners.forEach(e=>e())}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function rg(e){if(e.code!==nH.FAILED_PRECONDITION||e.message!==rp)throw e;nj("LocalStore","Unexpectedly lost primary lease")}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ry{constructor(e){this.nextCallback=null,this.catchCallback=null,this.result=void 0,this.error=void 0,this.isDone=!1,this.callbackAttached=!1,e(e=>{this.isDone=!0,this.result=e,this.nextCallback&&this.nextCallback(e)},e=>{this.isDone=!0,this.error=e,this.catchCallback&&this.catchCallback(e)})}catch(e){return this.next(void 0,e)}next(e,t){return this.callbackAttached&&nK(),this.callbackAttached=!0,this.isDone?this.error?this.wrapFailure(t,this.error):this.wrapSuccess(e,this.result):new ry((n,r)=>{this.nextCallback=t=>{this.wrapSuccess(e,t).next(n,r)},this.catchCallback=e=>{this.wrapFailure(t,e).next(n,r)}})}toPromise(){return new Promise((e,t)=>{this.next(e,t)})}wrapUserFunction(e){try{let t=e();return t instanceof ry?t:ry.resolve(t)}catch(e){return ry.reject(e)}}wrapSuccess(e,t){return e?this.wrapUserFunction(()=>e(t)):ry.resolve(t)}wrapFailure(e,t){return e?this.wrapUserFunction(()=>e(t)):ry.reject(t)}static resolve(e){return new ry((t,n)=>{t(e)})}static reject(e){return new ry((t,n)=>{n(e)})}static waitFor(e){return new ry((t,n)=>{let r=0,i=0,s=!1;e.forEach(e=>{++r,e.next(()=>{++i,s&&i===r&&t()},e=>n(e))}),s=!0,i===r&&t()})}static or(e){let t=ry.resolve(!1);for(let n of e)t=t.next(e=>e?ry.resolve(e):n());return t}static forEach(e,t){let n=[];return e.forEach((e,r)=>{n.push(t.call(this,e,r))}),this.waitFor(n)}static mapArray(e,t){return new ry((n,r)=>{let i=e.length,s=Array(i),a=0;for(let o=0;o<i;o++){let l=o;t(e[l]).next(e=>{s[l]=e,++a===i&&n(s)},e=>r(e))}})}static doWhile(e,t){return new ry((n,r)=>{let i=()=>{!0===e()?t().next(()=>{i()},r):n()};i()})}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rv{constructor(e,t){this.action=e,this.transaction=t,this.aborted=!1,this.P=new nY,this.transaction.oncomplete=()=>{this.P.resolve()},this.transaction.onabort=()=>{t.error?this.P.reject(new rb(e,t.error)):this.P.resolve()},this.transaction.onerror=t=>{let n=rk(t.target.error);this.P.reject(new rb(e,n))}}static open(e,t,n,r){try{return new rv(t,e.transaction(r,n))}catch(e){throw new rb(t,e)}}get v(){return this.P.promise}abort(e){e&&this.P.reject(e),this.aborted||(nj("SimpleDb","Aborting transaction:",e?e.message:"Client-initiated abort"),this.aborted=!0,this.transaction.abort())}V(){let e=this.transaction;this.aborted||"function"!=typeof e.commit||e.commit()}store(e){let t=this.transaction.objectStore(e);return new rT(t)}}class rw{constructor(e,t,n){this.name=e,this.version=t,this.S=n,12.2===rw.D((0,p.z$)())&&nz("Firestore persistence suffers from a bug in iOS 12.2 Safari that may cause your app to stop working. See https://stackoverflow.com/q/56496296/110915 for details and a potential workaround.")}static delete(e){return nj("SimpleDb","Removing database:",e),rE(window.indexedDB.deleteDatabase(e)).toPromise()}static C(){if(!(0,p.hl)())return!1;if(rw.N())return!0;let e=(0,p.z$)(),t=rw.D(e),n=rw.k(e);return!(e.indexOf("MSIE ")>0||e.indexOf("Trident/")>0||e.indexOf("Edge/")>0||0<t&&t<10||0<n&&n<4.5)}static N(){var e;return void 0!==nL&&"YES"===(null===(e=nL.env)||void 0===e?void 0:e.O)}static M(e,t){return e.store(t)}static D(e){let t=e.match(/i(?:phone|pad|pod) os ([\d_]+)/i),n=t?t[1].split("_").slice(0,2).join("."):"-1";return Number(n)}static k(e){let t=e.match(/Android ([\d.]+)/i),n=t?t[1].split(".").slice(0,2).join("."):"-1";return Number(n)}async F(e){return this.db||(nj("SimpleDb","Opening database:",this.name),this.db=await new Promise((t,n)=>{let r=indexedDB.open(this.name,this.version);r.onsuccess=e=>{let n=e.target.result;t(n)},r.onblocked=()=>{n(new rb(e,"Cannot upgrade IndexedDB schema while another tab is open. Close all tabs that access Firestore and reload this page to proceed."))},r.onerror=t=>{let r=t.target.error;"VersionError"===r.name?n(new nQ(nH.FAILED_PRECONDITION,"A newer version of the Firestore SDK was previously used and so the persisted data is not compatible with the version of the SDK you are now using. The SDK will operate with persistence disabled. If you need persistence, please re-upgrade to a newer version of the SDK or else clear the persisted IndexedDB data for your app to start fresh.")):"InvalidStateError"===r.name?n(new nQ(nH.FAILED_PRECONDITION,"Unable to open an IndexedDB connection. This could be due to running in a private browsing session on a browser whose private browsing sessions do not support IndexedDB: "+r)):n(new rb(e,r))},r.onupgradeneeded=e=>{nj("SimpleDb",'Database "'+this.name+'" requires upgrade from version:',e.oldVersion);let t=e.target.result;this.S.$(t,r.transaction,e.oldVersion,this.version).next(()=>{nj("SimpleDb","Database upgrade to version "+this.version+" complete")})}})),this.B&&(this.db.onversionchange=e=>this.B(e)),this.db}L(e){this.B=e,this.db&&(this.db.onversionchange=t=>e(t))}async runTransaction(e,t,n,r){let i="readonly"===t,s=0;for(;;){++s;try{this.db=await this.F(e);let t=rv.open(this.db,e,i?"readonly":"readwrite",n),s=r(t).next(e=>(t.V(),e)).catch(e=>(t.abort(e),ry.reject(e))).toPromise();return s.catch(()=>{}),await t.v,s}catch(t){let e="FirebaseError"!==t.name&&s<3;if(nj("SimpleDb","Transaction failed with error:",t.message,"Retrying:",e),this.close(),!e)return Promise.reject(t)}}}close(){this.db&&this.db.close(),this.db=void 0}}class r_{constructor(e){this.q=e,this.U=!1,this.K=null}get isDone(){return this.U}get G(){return this.K}set cursor(e){this.q=e}done(){this.U=!0}j(e){this.K=e}delete(){return rE(this.q.delete())}}class rb extends nQ{constructor(e,t){super(nH.UNAVAILABLE,`IndexedDB transaction '${e}' failed: ${t}`),this.name="IndexedDbTransactionError"}}function rI(e){return"IndexedDbTransactionError"===e.name}class rT{constructor(e){this.store=e}put(e,t){let n;return void 0!==t?(nj("SimpleDb","PUT",this.store.name,e,t),n=this.store.put(t,e)):(nj("SimpleDb","PUT",this.store.name,"<auto-key>",e),n=this.store.put(e)),rE(n)}add(e){return nj("SimpleDb","ADD",this.store.name,e,e),rE(this.store.add(e))}get(e){return rE(this.store.get(e)).next(t=>(void 0===t&&(t=null),nj("SimpleDb","GET",this.store.name,e,t),t))}delete(e){return nj("SimpleDb","DELETE",this.store.name,e),rE(this.store.delete(e))}count(){return nj("SimpleDb","COUNT",this.store.name),rE(this.store.count())}W(e,t){let n=this.options(e,t);if(n.index||"function"!=typeof this.store.getAll){let e=this.cursor(n),t=[];return this.H(e,(e,n)=>{t.push(n)}).next(()=>t)}{let e=this.store.getAll(n.range);return new ry((t,n)=>{e.onerror=e=>{n(e.target.error)},e.onsuccess=e=>{t(e.target.result)}})}}J(e,t){let n=this.store.getAll(e,null===t?void 0:t);return new ry((e,t)=>{n.onerror=e=>{t(e.target.error)},n.onsuccess=t=>{e(t.target.result)}})}Y(e,t){nj("SimpleDb","DELETE ALL",this.store.name);let n=this.options(e,t);n.X=!1;let r=this.cursor(n);return this.H(r,(e,t,n)=>n.delete())}Z(e,t){let n;t?n=e:(n={},t=e);let r=this.cursor(n);return this.H(r,t)}tt(e){let t=this.cursor({});return new ry((n,r)=>{t.onerror=e=>{let t=rk(e.target.error);r(t)},t.onsuccess=t=>{let r=t.target.result;r?e(r.primaryKey,r.value).next(e=>{e?r.continue():n()}):n()}})}H(e,t){let n=[];return new ry((r,i)=>{e.onerror=e=>{i(e.target.error)},e.onsuccess=e=>{let i=e.target.result;if(!i)return void r();let s=new r_(i),a=t(i.primaryKey,i.value,s);if(a instanceof ry){let e=a.catch(e=>(s.done(),ry.reject(e)));n.push(e)}s.isDone?r():null===s.G?i.continue():i.continue(s.G)}}).next(()=>ry.waitFor(n))}options(e,t){let n;return void 0!==e&&("string"==typeof e?n=e:t=e),{index:n,range:t}}cursor(e){let t="next";if(e.reverse&&(t="prev"),e.index){let n=this.store.index(e.index);return e.X?n.openKeyCursor(e.range,t):n.openCursor(e.range,t)}return this.store.openCursor(e.range,t)}}function rE(e){return new ry((t,n)=>{e.onsuccess=e=>{let n=e.target.result;t(n)},e.onerror=e=>{let t=rk(e.target.error);n(t)}})}let rS=!1;function rk(e){let t=rw.D((0,p.z$)());if(t>=12.2&&t<13){let t="An internal error was encountered in the Indexed Database server";if(e.message.indexOf(t)>=0){let e=new nQ("internal",`IOS_INDEXEDDB_BUG1: IndexedDb has thrown '${t}'. This is likely due to an unavoidable bug in iOS. See https://stackoverflow.com/q/56496296/110915 for details and a potential workaround.`);return rS||(rS=!0,setTimeout(()=>{throw e},0)),e}}return e}class rA{constructor(e,t){this.asyncQueue=e,this.et=t,this.task=null}start(){this.nt(15e3)}stop(){this.task&&(this.task.cancel(),this.task=null)}get started(){return null!==this.task}nt(e){nj("IndexBackiller",`Scheduled in ${e}ms`),this.task=this.asyncQueue.enqueueAfterDelay("index_backfill",e,async()=>{this.task=null;try{nj("IndexBackiller",`Documents written: ${await this.et.st()}`)}catch(e){rI(e)?nj("IndexBackiller","Ignoring IndexedDB error during index backfill: ",e):await rg(e)}await this.nt(6e4)})}}class rC{constructor(e,t){this.localStore=e,this.persistence=t}async st(e=50){return this.persistence.runTransaction("Backfill Indexes","readwrite-primary",t=>this.it(t,e))}it(e,t){let n=new Set,r=t,i=!0;return ry.doWhile(()=>!0===i&&r>0,()=>this.localStore.indexManager.getNextCollectionGroupToUpdate(e).next(t=>{if(null!==t&&!n.has(t))return nj("IndexBackiller",`Processing collection: ${t}`),this.rt(e,t,r).next(e=>{r-=e,n.add(t)});i=!1})).next(()=>t-r)}rt(e,t,n){return this.localStore.indexManager.getMinOffsetFromCollectionGroup(e,t).next(r=>this.localStore.localDocuments.getNextDocuments(e,t,r,n).next(n=>{let i=n.changes;return this.localStore.indexManager.updateIndexEntries(e,i).next(()=>this.ot(r,n)).next(n=>(nj("IndexBackiller",`Updating offset: ${n}`),this.localStore.indexManager.updateCollectionGroup(e,t,n))).next(()=>i.size)}))}ot(e,t){let n=e;return t.changes.forEach((e,t)=>{let r=rh(t);rf(r,n)>0&&(n=r)}),new rd(n.readTime,n.documentKey,Math.max(t.batchId,e.largestBatchId))}}/**
 * @license
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rx{constructor(e,t){this.previousValue=e,t&&(t.sequenceNumberHandler=e=>this.ut(e),this.ct=e=>t.writeSequenceNumber(e))}ut(e){return this.previousValue=Math.max(e,this.previousValue),this.previousValue}next(){let e=++this.previousValue;return this.ct&&this.ct(e),e}}rx.at=-1;/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rN{constructor(e,t,n,r,i,s,a,o){this.databaseId=e,this.appId=t,this.persistenceKey=n,this.host=r,this.ssl=i,this.forceLongPolling=s,this.autoDetectLongPolling=a,this.useFetchStreams=o}}class rR{constructor(e,t){this.projectId=e,this.database=t||"(default)"}static empty(){return new rR("","")}get isDefaultDatabase(){return"(default)"===this.database}isEqual(e){return e instanceof rR&&e.projectId===this.projectId&&e.database===this.database}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function rD(e){let t=0;for(let n in e)Object.prototype.hasOwnProperty.call(e,n)&&t++;return t}function rO(e,t){for(let n in e)Object.prototype.hasOwnProperty.call(e,n)&&t(n,e[n])}function rP(e){for(let t in e)if(Object.prototype.hasOwnProperty.call(e,t))return!1;return!0}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function rL(e){return null==e}function rM(e){return 0===e&&1/e==-1/0}function rU(e){return"number"==typeof e&&Number.isInteger(e)&&!rM(e)&&e<=Number.MAX_SAFE_INTEGER&&e>=Number.MIN_SAFE_INTEGER}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function rF(){return"undefined"!=typeof atob}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rV{constructor(e){this.binaryString=e}static fromBase64String(e){let t=atob(e);return new rV(t)}static fromUint8Array(e){let t=function(e){let t="";for(let n=0;n<e.length;++n)t+=String.fromCharCode(e[n]);return t}(e);return new rV(t)}[Symbol.iterator](){let e=0;return{next:()=>e<this.binaryString.length?{value:this.binaryString.charCodeAt(e++),done:!1}:{value:void 0,done:!0}}}toBase64(){return btoa(this.binaryString)}toUint8Array(){return function(e){let t=new Uint8Array(e.length);for(let n=0;n<e.length;n++)t[n]=e.charCodeAt(n);return t}(this.binaryString)}approximateByteSize(){return 2*this.binaryString.length}compareTo(e){return n5(this.binaryString,e.binaryString)}isEqual(e){return this.binaryString===e.binaryString}}rV.EMPTY_BYTE_STRING=new rV("");let rq=RegExp(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.(\d+))?Z$/);function rB(e){if(e||nK(),"string"==typeof e){let t=0,n=rq.exec(e);if(n||nK(),n[1]){let e=n[1];t=Number(e=(e+"000000000").substr(0,9))}let r=new Date(e);return{seconds:Math.floor(r.getTime()/1e3),nanos:t}}return{seconds:rj(e.seconds),nanos:rj(e.nanos)}}function rj(e){return"number"==typeof e?e:"string"==typeof e?Number(e):0}function rz(e){return"string"==typeof e?rV.fromBase64String(e):rV.fromUint8Array(e)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function r$(e){var t,n;return"server_timestamp"===(null===(n=((null===(t=null==e?void 0:e.mapValue)||void 0===t?void 0:t.fields)||{}).__type__)||void 0===n?void 0:n.stringValue)}function rG(e){let t=rB(e.mapValue.fields.__local_write_time__.timestampValue);return new n8(t.seconds,t.nanos)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let rK={mapValue:{fields:{__type__:{stringValue:"__max__"}}}},rW={nullValue:"NULL_VALUE"};function rH(e){return"nullValue"in e?0:"booleanValue"in e?1:"integerValue"in e||"doubleValue"in e?2:"timestampValue"in e?3:"stringValue"in e?5:"bytesValue"in e?6:"referenceValue"in e?7:"geoPointValue"in e?8:"arrayValue"in e?9:"mapValue"in e?r$(e)?4:r9(e)?9007199254740991:10:nK()}function rQ(e,t){if(e===t)return!0;let n=rH(e);if(n!==rH(t))return!1;switch(n){case 0:case 9007199254740991:return!0;case 1:return e.booleanValue===t.booleanValue;case 4:return rG(e).isEqual(rG(t));case 3:return function(e,t){if("string"==typeof e.timestampValue&&"string"==typeof t.timestampValue&&e.timestampValue.length===t.timestampValue.length)return e.timestampValue===t.timestampValue;let n=rB(e.timestampValue),r=rB(t.timestampValue);return n.seconds===r.seconds&&n.nanos===r.nanos}(e,t);case 5:return e.stringValue===t.stringValue;case 6:return rz(e.bytesValue).isEqual(rz(t.bytesValue));case 7:return e.referenceValue===t.referenceValue;case 8:return rj(e.geoPointValue.latitude)===rj(t.geoPointValue.latitude)&&rj(e.geoPointValue.longitude)===rj(t.geoPointValue.longitude);case 2:return function(e,t){if("integerValue"in e&&"integerValue"in t)return rj(e.integerValue)===rj(t.integerValue);if("doubleValue"in e&&"doubleValue"in t){let n=rj(e.doubleValue),r=rj(t.doubleValue);return n===r?rM(n)===rM(r):isNaN(n)&&isNaN(r)}return!1}(e,t);case 9:return n9(e.arrayValue.values||[],t.arrayValue.values||[],rQ);case 10:return function(e,t){let n=e.mapValue.fields||{},r=t.mapValue.fields||{};if(rD(n)!==rD(r))return!1;for(let e in n)if(n.hasOwnProperty(e)&&(void 0===r[e]||!rQ(n[e],r[e])))return!1;return!0}(e,t);default:return nK()}}function rY(e,t){return void 0!==(e.values||[]).find(e=>rQ(e,t))}function rX(e,t){if(e===t)return 0;let n=rH(e),r=rH(t);if(n!==r)return n5(n,r);switch(n){case 0:case 9007199254740991:return 0;case 1:return n5(e.booleanValue,t.booleanValue);case 2:return function(e,t){let n=rj(e.integerValue||e.doubleValue),r=rj(t.integerValue||t.doubleValue);return n<r?-1:n>r?1:n===r?0:isNaN(n)?isNaN(r)?0:-1:1}(e,t);case 3:return rJ(e.timestampValue,t.timestampValue);case 4:return rJ(rG(e),rG(t));case 5:return n5(e.stringValue,t.stringValue);case 6:return function(e,t){let n=rz(e),r=rz(t);return n.compareTo(r)}(e.bytesValue,t.bytesValue);case 7:return function(e,t){let n=e.split("/"),r=t.split("/");for(let e=0;e<n.length&&e<r.length;e++){let t=n5(n[e],r[e]);if(0!==t)return t}return n5(n.length,r.length)}(e.referenceValue,t.referenceValue);case 8:return function(e,t){let n=n5(rj(e.latitude),rj(t.latitude));return 0!==n?n:n5(rj(e.longitude),rj(t.longitude))}(e.geoPointValue,t.geoPointValue);case 9:return function(e,t){let n=e.values||[],r=t.values||[];for(let e=0;e<n.length&&e<r.length;++e){let t=rX(n[e],r[e]);if(t)return t}return n5(n.length,r.length)}(e.arrayValue,t.arrayValue);case 10:return function(e,t){if(e===rK.mapValue&&t===rK.mapValue)return 0;if(e===rK.mapValue)return 1;if(t===rK.mapValue)return -1;let n=e.fields||{},r=Object.keys(n),i=t.fields||{},s=Object.keys(i);r.sort(),s.sort();for(let e=0;e<r.length&&e<s.length;++e){let t=n5(r[e],s[e]);if(0!==t)return t;let a=rX(n[r[e]],i[s[e]]);if(0!==a)return a}return n5(r.length,s.length)}(e.mapValue,t.mapValue);default:throw nK()}}function rJ(e,t){if("string"==typeof e&&"string"==typeof t&&e.length===t.length)return n5(e,t);let n=rB(e),r=rB(t),i=n5(n.seconds,r.seconds);return 0!==i?i:n5(n.nanos,r.nanos)}function rZ(e){var t,n;return"nullValue"in e?"null":"booleanValue"in e?""+e.booleanValue:"integerValue"in e?""+e.integerValue:"doubleValue"in e?""+e.doubleValue:"timestampValue"in e?function(e){let t=rB(e);return`time(${t.seconds},${t.nanos})`}(e.timestampValue):"stringValue"in e?e.stringValue:"bytesValue"in e?rz(e.bytesValue).toBase64():"referenceValue"in e?(n=e.referenceValue,ri.fromName(n).toString()):"geoPointValue"in e?`geo(${(t=e.geoPointValue).latitude},${t.longitude})`:"arrayValue"in e?function(e){let t="[",n=!0;for(let r of e.values||[])n?n=!1:t+=",",t+=rZ(r);return t+"]"}(e.arrayValue):"mapValue"in e?function(e){let t=Object.keys(e.fields||{}).sort(),n="{",r=!0;for(let i of t)r?r=!1:n+=",",n+=`${i}:${rZ(e.fields[i])}`;return n+"}"}(e.mapValue):nK()}function r0(e,t){return{referenceValue:`projects/${e.projectId}/databases/${e.database}/documents/${t.path.canonicalString()}`}}function r1(e){return!!e&&"integerValue"in e}function r2(e){return!!e&&"arrayValue"in e}function r3(e){return!!e&&"nullValue"in e}function r4(e){return!!e&&"doubleValue"in e&&isNaN(Number(e.doubleValue))}function r6(e){return!!e&&"mapValue"in e}function r5(e){if(e.geoPointValue)return{geoPointValue:Object.assign({},e.geoPointValue)};if(e.timestampValue&&"object"==typeof e.timestampValue)return{timestampValue:Object.assign({},e.timestampValue)};if(e.mapValue){let t={mapValue:{fields:{}}};return rO(e.mapValue.fields,(e,n)=>t.mapValue.fields[e]=r5(n)),t}if(e.arrayValue){let t={arrayValue:{values:[]}};for(let n=0;n<(e.arrayValue.values||[]).length;++n)t.arrayValue.values[n]=r5(e.arrayValue.values[n]);return t}return Object.assign({},e)}function r9(e){return"__max__"===(((e.mapValue||{}).fields||{}).__type__||{}).stringValue}function r8(e,t){let n=rX(e.value,t.value);return 0!==n?n:e.inclusive&&!t.inclusive?-1:!e.inclusive&&t.inclusive?1:0}function r7(e,t){let n=rX(e.value,t.value);return 0!==n?n:e.inclusive&&!t.inclusive?1:!e.inclusive&&t.inclusive?-1:0}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ie{constructor(e,t){this.position=e,this.inclusive=t}}function it(e,t,n){let r=0;for(let i=0;i<e.position.length;i++){let s=t[i],a=e.position[i];if(r=s.field.isKeyField()?ri.comparator(ri.fromName(a.referenceValue),n.key):rX(a,n.data.field(s.field)),"desc"===s.dir&&(r*=-1),0!==r)break}return r}function ir(e,t){if(null===e)return null===t;if(null===t||e.inclusive!==t.inclusive||e.position.length!==t.position.length)return!1;for(let n=0;n<e.position.length;n++)if(!rQ(e.position[n],t.position[n]))return!1;return!0}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ii{}class is extends ii{constructor(e,t,n){super(),this.field=e,this.op=t,this.value=n}static create(e,t,n){return e.isKeyField()?"in"===t||"not-in"===t?this.createKeyFieldInFilter(e,t,n):new id(e,t,n):"array-contains"===t?new iy(e,n):"in"===t?new iv(e,n):"not-in"===t?new iw(e,n):"array-contains-any"===t?new i_(e,n):new is(e,t,n)}static createKeyFieldInFilter(e,t,n){return"in"===t?new ip(e,n):new im(e,n)}matches(e){let t=e.data.field(this.field);return"!="===this.op?null!==t&&this.matchesComparison(rX(t,this.value)):null!==t&&rH(this.value)===rH(t)&&this.matchesComparison(rX(t,this.value))}matchesComparison(e){switch(this.op){case"<":return e<0;case"<=":return e<=0;case"==":return 0===e;case"!=":return 0!==e;case">":return e>0;case">=":return e>=0;default:return nK()}}isInequality(){return["<","<=",">",">=","!=","not-in"].indexOf(this.op)>=0}getFlattenedFilters(){return[this]}getFilters(){return[this]}getFirstInequalityField(){return this.isInequality()?this.field:null}}class ia extends ii{constructor(e,t){super(),this.filters=e,this.op=t,this.ht=null}static create(e,t){return new ia(e,t)}matches(e){return io(this)?void 0===this.filters.find(t=>!t.matches(e)):void 0!==this.filters.find(t=>t.matches(e))}getFlattenedFilters(){return null!==this.ht||(this.ht=this.filters.reduce((e,t)=>e.concat(t.getFlattenedFilters()),[])),this.ht}getFilters(){return Object.assign([],this.filters)}getFirstInequalityField(){let e=this.lt(e=>e.isInequality());return null!==e?e.field:null}lt(e){for(let t of this.getFlattenedFilters())if(e(t))return t;return null}}function io(e){return"and"===e.op}function il(e){return"or"===e.op}function iu(e){return ic(e)&&io(e)}function ic(e){for(let t of e.filters)if(t instanceof ia)return!1;return!0}function ih(e,t){let n=e.filters.concat(t);return ia.create(n,e.op)}class id extends is{constructor(e,t,n){super(e,t,n),this.key=ri.fromName(n.referenceValue)}matches(e){let t=ri.comparator(e.key,this.key);return this.matchesComparison(t)}}class ip extends is{constructor(e,t){super(e,"in",t),this.keys=ig("in",t)}matches(e){return this.keys.some(t=>t.isEqual(e.key))}}class im extends is{constructor(e,t){super(e,"not-in",t),this.keys=ig("not-in",t)}matches(e){return!this.keys.some(t=>t.isEqual(e.key))}}function ig(e,t){var n;return((null===(n=t.arrayValue)||void 0===n?void 0:n.values)||[]).map(e=>ri.fromName(e.referenceValue))}class iy extends is{constructor(e,t){super(e,"array-contains",t)}matches(e){let t=e.data.field(this.field);return r2(t)&&rY(t.arrayValue,this.value)}}class iv extends is{constructor(e,t){super(e,"in",t)}matches(e){let t=e.data.field(this.field);return null!==t&&rY(this.value.arrayValue,t)}}class iw extends is{constructor(e,t){super(e,"not-in",t)}matches(e){if(rY(this.value.arrayValue,{nullValue:"NULL_VALUE"}))return!1;let t=e.data.field(this.field);return null!==t&&!rY(this.value.arrayValue,t)}}class i_ extends is{constructor(e,t){super(e,"array-contains-any",t)}matches(e){let t=e.data.field(this.field);return!(!r2(t)||!t.arrayValue.values)&&t.arrayValue.values.some(e=>rY(this.value.arrayValue,e))}}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ib{constructor(e,t="asc"){this.field=e,this.dir=t}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iI{constructor(e,t){this.comparator=e,this.root=t||iE.EMPTY}insert(e,t){return new iI(this.comparator,this.root.insert(e,t,this.comparator).copy(null,null,iE.BLACK,null,null))}remove(e){return new iI(this.comparator,this.root.remove(e,this.comparator).copy(null,null,iE.BLACK,null,null))}get(e){let t=this.root;for(;!t.isEmpty();){let n=this.comparator(e,t.key);if(0===n)return t.value;n<0?t=t.left:n>0&&(t=t.right)}return null}indexOf(e){let t=0,n=this.root;for(;!n.isEmpty();){let r=this.comparator(e,n.key);if(0===r)return t+n.left.size;r<0?n=n.left:(t+=n.left.size+1,n=n.right)}return -1}isEmpty(){return this.root.isEmpty()}get size(){return this.root.size}minKey(){return this.root.minKey()}maxKey(){return this.root.maxKey()}inorderTraversal(e){return this.root.inorderTraversal(e)}forEach(e){this.inorderTraversal((t,n)=>(e(t,n),!1))}toString(){let e=[];return this.inorderTraversal((t,n)=>(e.push(`${t}:${n}`),!1)),`{${e.join(", ")}}`}reverseTraversal(e){return this.root.reverseTraversal(e)}getIterator(){return new iT(this.root,null,this.comparator,!1)}getIteratorFrom(e){return new iT(this.root,e,this.comparator,!1)}getReverseIterator(){return new iT(this.root,null,this.comparator,!0)}getReverseIteratorFrom(e){return new iT(this.root,e,this.comparator,!0)}}class iT{constructor(e,t,n,r){this.isReverse=r,this.nodeStack=[];let i=1;for(;!e.isEmpty();)if(i=t?n(e.key,t):1,t&&r&&(i*=-1),i<0)e=this.isReverse?e.left:e.right;else{if(0===i){this.nodeStack.push(e);break}this.nodeStack.push(e),e=this.isReverse?e.right:e.left}}getNext(){let e=this.nodeStack.pop(),t={key:e.key,value:e.value};if(this.isReverse)for(e=e.left;!e.isEmpty();)this.nodeStack.push(e),e=e.right;else for(e=e.right;!e.isEmpty();)this.nodeStack.push(e),e=e.left;return t}hasNext(){return this.nodeStack.length>0}peek(){if(0===this.nodeStack.length)return null;let e=this.nodeStack[this.nodeStack.length-1];return{key:e.key,value:e.value}}}class iE{constructor(e,t,n,r,i){this.key=e,this.value=t,this.color=null!=n?n:iE.RED,this.left=null!=r?r:iE.EMPTY,this.right=null!=i?i:iE.EMPTY,this.size=this.left.size+1+this.right.size}copy(e,t,n,r,i){return new iE(null!=e?e:this.key,null!=t?t:this.value,null!=n?n:this.color,null!=r?r:this.left,null!=i?i:this.right)}isEmpty(){return!1}inorderTraversal(e){return this.left.inorderTraversal(e)||e(this.key,this.value)||this.right.inorderTraversal(e)}reverseTraversal(e){return this.right.reverseTraversal(e)||e(this.key,this.value)||this.left.reverseTraversal(e)}min(){return this.left.isEmpty()?this:this.left.min()}minKey(){return this.min().key}maxKey(){return this.right.isEmpty()?this.key:this.right.maxKey()}insert(e,t,n){let r=this,i=n(e,r.key);return(r=i<0?r.copy(null,null,null,r.left.insert(e,t,n),null):0===i?r.copy(null,t,null,null,null):r.copy(null,null,null,null,r.right.insert(e,t,n))).fixUp()}removeMin(){if(this.left.isEmpty())return iE.EMPTY;let e=this;return e.left.isRed()||e.left.left.isRed()||(e=e.moveRedLeft()),(e=e.copy(null,null,null,e.left.removeMin(),null)).fixUp()}remove(e,t){let n,r=this;if(0>t(e,r.key))r.left.isEmpty()||r.left.isRed()||r.left.left.isRed()||(r=r.moveRedLeft()),r=r.copy(null,null,null,r.left.remove(e,t),null);else{if(r.left.isRed()&&(r=r.rotateRight()),r.right.isEmpty()||r.right.isRed()||r.right.left.isRed()||(r=r.moveRedRight()),0===t(e,r.key)){if(r.right.isEmpty())return iE.EMPTY;n=r.right.min(),r=r.copy(n.key,n.value,null,null,r.right.removeMin())}r=r.copy(null,null,null,null,r.right.remove(e,t))}return r.fixUp()}isRed(){return this.color}fixUp(){let e=this;return e.right.isRed()&&!e.left.isRed()&&(e=e.rotateLeft()),e.left.isRed()&&e.left.left.isRed()&&(e=e.rotateRight()),e.left.isRed()&&e.right.isRed()&&(e=e.colorFlip()),e}moveRedLeft(){let e=this.colorFlip();return e.right.left.isRed()&&(e=(e=(e=e.copy(null,null,null,null,e.right.rotateRight())).rotateLeft()).colorFlip()),e}moveRedRight(){let e=this.colorFlip();return e.left.left.isRed()&&(e=(e=e.rotateRight()).colorFlip()),e}rotateLeft(){let e=this.copy(null,null,iE.RED,null,this.right.left);return this.right.copy(null,null,this.color,e,null)}rotateRight(){let e=this.copy(null,null,iE.RED,this.left.right,null);return this.left.copy(null,null,this.color,null,e)}colorFlip(){let e=this.left.copy(null,null,!this.left.color,null,null),t=this.right.copy(null,null,!this.right.color,null,null);return this.copy(null,null,!this.color,e,t)}checkMaxDepth(){let e=this.check();return Math.pow(2,e)<=this.size+1}check(){if(this.isRed()&&this.left.isRed()||this.right.isRed())throw nK();let e=this.left.check();if(e!==this.right.check())throw nK();return e+(this.isRed()?0:1)}}iE.EMPTY=null,iE.RED=!0,iE.BLACK=!1,iE.EMPTY=new class{constructor(){this.size=0}get key(){throw nK()}get value(){throw nK()}get color(){throw nK()}get left(){throw nK()}get right(){throw nK()}copy(e,t,n,r,i){return this}insert(e,t,n){return new iE(e,t)}remove(e,t){return this}isEmpty(){return!0}inorderTraversal(e){return!1}reverseTraversal(e){return!1}minKey(){return null}maxKey(){return null}isRed(){return!1}checkMaxDepth(){return!0}check(){return 0}};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iS{constructor(e){this.comparator=e,this.data=new iI(this.comparator)}has(e){return null!==this.data.get(e)}first(){return this.data.minKey()}last(){return this.data.maxKey()}get size(){return this.data.size}indexOf(e){return this.data.indexOf(e)}forEach(e){this.data.inorderTraversal((t,n)=>(e(t),!1))}forEachInRange(e,t){let n=this.data.getIteratorFrom(e[0]);for(;n.hasNext();){let r=n.getNext();if(this.comparator(r.key,e[1])>=0)return;t(r.key)}}forEachWhile(e,t){let n;for(n=void 0!==t?this.data.getIteratorFrom(t):this.data.getIterator();n.hasNext();)if(!e(n.getNext().key))return}firstAfterOrEqual(e){let t=this.data.getIteratorFrom(e);return t.hasNext()?t.getNext().key:null}getIterator(){return new ik(this.data.getIterator())}getIteratorFrom(e){return new ik(this.data.getIteratorFrom(e))}add(e){return this.copy(this.data.remove(e).insert(e,!0))}delete(e){return this.has(e)?this.copy(this.data.remove(e)):this}isEmpty(){return this.data.isEmpty()}unionWith(e){let t=this;return t.size<e.size&&(t=e,e=this),e.forEach(e=>{t=t.add(e)}),t}isEqual(e){if(!(e instanceof iS)||this.size!==e.size)return!1;let t=this.data.getIterator(),n=e.data.getIterator();for(;t.hasNext();){let e=t.getNext().key,r=n.getNext().key;if(0!==this.comparator(e,r))return!1}return!0}toArray(){let e=[];return this.forEach(t=>{e.push(t)}),e}toString(){let e=[];return this.forEach(t=>e.push(t)),"SortedSet("+e.toString()+")"}copy(e){let t=new iS(this.comparator);return t.data=e,t}}class ik{constructor(e){this.iter=e}getNext(){return this.iter.getNext().key}hasNext(){return this.iter.hasNext()}}function iA(e){return e.hasNext()?e.getNext():void 0}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iC{constructor(e){this.fields=e,e.sort(rr.comparator)}static empty(){return new iC([])}unionWith(e){let t=new iS(rr.comparator);for(let e of this.fields)t=t.add(e);for(let n of e)t=t.add(n);return new iC(t.toArray())}covers(e){for(let t of this.fields)if(t.isPrefixOf(e))return!0;return!1}isEqual(e){return n9(this.fields,e.fields,(e,t)=>e.isEqual(t))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ix{constructor(e){this.value=e}static empty(){return new ix({mapValue:{}})}field(e){if(e.isEmpty())return this.value;{let t=this.value;for(let n=0;n<e.length-1;++n)if(!r6(t=(t.mapValue.fields||{})[e.get(n)]))return null;return(t=(t.mapValue.fields||{})[e.lastSegment()])||null}}set(e,t){this.getFieldsMap(e.popLast())[e.lastSegment()]=r5(t)}setAll(e){let t=rr.emptyPath(),n={},r=[];e.forEach((e,i)=>{if(!t.isImmediateParentOf(i)){let e=this.getFieldsMap(t);this.applyChanges(e,n,r),n={},r=[],t=i.popLast()}e?n[i.lastSegment()]=r5(e):r.push(i.lastSegment())});let i=this.getFieldsMap(t);this.applyChanges(i,n,r)}delete(e){let t=this.field(e.popLast());r6(t)&&t.mapValue.fields&&delete t.mapValue.fields[e.lastSegment()]}isEqual(e){return rQ(this.value,e.value)}getFieldsMap(e){let t=this.value;t.mapValue.fields||(t.mapValue={fields:{}});for(let n=0;n<e.length;++n){let r=t.mapValue.fields[e.get(n)];r6(r)&&r.mapValue.fields||(r={mapValue:{fields:{}}},t.mapValue.fields[e.get(n)]=r),t=r}return t.mapValue.fields}applyChanges(e,t,n){for(let r of(rO(t,(t,n)=>e[t]=n),n))delete e[r]}clone(){return new ix(r5(this.value))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iN{constructor(e,t,n,r,i,s,a){this.key=e,this.documentType=t,this.version=n,this.readTime=r,this.createTime=i,this.data=s,this.documentState=a}static newInvalidDocument(e){return new iN(e,0,n7.min(),n7.min(),n7.min(),ix.empty(),0)}static newFoundDocument(e,t,n,r){return new iN(e,1,t,n7.min(),n,r,0)}static newNoDocument(e,t){return new iN(e,2,t,n7.min(),n7.min(),ix.empty(),0)}static newUnknownDocument(e,t){return new iN(e,3,t,n7.min(),n7.min(),ix.empty(),2)}convertToFoundDocument(e,t){return this.createTime.isEqual(n7.min())&&(2===this.documentType||0===this.documentType)&&(this.createTime=e),this.version=e,this.documentType=1,this.data=t,this.documentState=0,this}convertToNoDocument(e){return this.version=e,this.documentType=2,this.data=ix.empty(),this.documentState=0,this}convertToUnknownDocument(e){return this.version=e,this.documentType=3,this.data=ix.empty(),this.documentState=2,this}setHasCommittedMutations(){return this.documentState=2,this}setHasLocalMutations(){return this.documentState=1,this.version=n7.min(),this}setReadTime(e){return this.readTime=e,this}get hasLocalMutations(){return 1===this.documentState}get hasCommittedMutations(){return 2===this.documentState}get hasPendingWrites(){return this.hasLocalMutations||this.hasCommittedMutations}isValidDocument(){return 0!==this.documentType}isFoundDocument(){return 1===this.documentType}isNoDocument(){return 2===this.documentType}isUnknownDocument(){return 3===this.documentType}isEqual(e){return e instanceof iN&&this.key.isEqual(e.key)&&this.version.isEqual(e.version)&&this.documentType===e.documentType&&this.documentState===e.documentState&&this.data.isEqual(e.data)}mutableCopy(){return new iN(this.key,this.documentType,this.version,this.readTime,this.createTime,this.data.clone(),this.documentState)}toString(){return`Document(${this.key}, ${this.version}, ${JSON.stringify(this.data.value)}, {createTime: ${this.createTime}}), {documentType: ${this.documentType}}), {documentState: ${this.documentState}})`}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iR{constructor(e,t=null,n=[],r=[],i=null,s=null,a=null){this.path=e,this.collectionGroup=t,this.orderBy=n,this.filters=r,this.limit=i,this.startAt=s,this.endAt=a,this.ft=null}}function iD(e,t=null,n=[],r=[],i=null,s=null,a=null){return new iR(e,t,n,r,i,s,a)}function iO(e){let t=e;if(null===t.ft){let e=t.path.canonicalString();null!==t.collectionGroup&&(e+="|cg:"+t.collectionGroup),e+="|f:"+t.filters.map(e=>(function e(t){if(t instanceof is)return t.field.canonicalString()+t.op.toString()+rZ(t.value);if(iu(t))return t.filters.map(t=>e(t)).join(",");{let n=t.filters.map(t=>e(t)).join(",");return`${t.op}(${n})`}})(e)).join(",")+"|ob:"+t.orderBy.map(e=>e.field.canonicalString()+e.dir).join(","),rL(t.limit)||(e+="|l:"+t.limit),t.startAt&&(e+="|lb:"+(t.startAt.inclusive?"b:":"a:")+t.startAt.position.map(e=>rZ(e)).join(",")),t.endAt&&(e+="|ub:"+(t.endAt.inclusive?"a:":"b:")+t.endAt.position.map(e=>rZ(e)).join(",")),t.ft=e}return t.ft}function iP(e,t){if(e.limit!==t.limit||e.orderBy.length!==t.orderBy.length)return!1;for(let i=0;i<e.orderBy.length;i++){var n,r;if(n=e.orderBy[i],r=t.orderBy[i],!(n.dir===r.dir&&n.field.isEqual(r.field)))return!1}if(e.filters.length!==t.filters.length)return!1;for(let n=0;n<e.filters.length;n++)if(!function e(t,n){return t instanceof is?n instanceof is&&t.op===n.op&&t.field.isEqual(n.field)&&rQ(t.value,n.value):t instanceof ia?n instanceof ia&&t.op===n.op&&t.filters.length===n.filters.length&&t.filters.reduce((t,r,i)=>t&&e(r,n.filters[i]),!0):void nK()}(e.filters[n],t.filters[n]))return!1;return e.collectionGroup===t.collectionGroup&&!!e.path.isEqual(t.path)&&!!ir(e.startAt,t.startAt)&&ir(e.endAt,t.endAt)}function iL(e){return ri.isDocumentKey(e.path)&&null===e.collectionGroup&&0===e.filters.length}function iM(e,t){return e.filters.filter(e=>e instanceof is&&e.field.isEqual(t))}function iU(e,t,n){let r=rW,i=!0;for(let n of iM(e,t)){let e=rW,t=!0;switch(n.op){case"<":case"<=":var s;e="nullValue"in(s=n.value)?rW:"booleanValue"in s?{booleanValue:!1}:"integerValue"in s||"doubleValue"in s?{doubleValue:NaN}:"timestampValue"in s?{timestampValue:{seconds:Number.MIN_SAFE_INTEGER}}:"stringValue"in s?{stringValue:""}:"bytesValue"in s?{bytesValue:""}:"referenceValue"in s?r0(rR.empty(),ri.empty()):"geoPointValue"in s?{geoPointValue:{latitude:-90,longitude:-180}}:"arrayValue"in s?{arrayValue:{}}:"mapValue"in s?{mapValue:{}}:nK();break;case"==":case"in":case">=":e=n.value;break;case">":e=n.value,t=!1;break;case"!=":case"not-in":e=rW}0>r8({value:r,inclusive:i},{value:e,inclusive:t})&&(r=e,i=t)}if(null!==n){for(let s=0;s<e.orderBy.length;++s)if(e.orderBy[s].field.isEqual(t)){let e=n.position[s];0>r8({value:r,inclusive:i},{value:e,inclusive:n.inclusive})&&(r=e,i=n.inclusive);break}}return{value:r,inclusive:i}}function iF(e,t,n){let r=rK,i=!0;for(let n of iM(e,t)){let e=rK,t=!0;switch(n.op){case">=":case">":var s;e="nullValue"in(s=n.value)?{booleanValue:!1}:"booleanValue"in s?{doubleValue:NaN}:"integerValue"in s||"doubleValue"in s?{timestampValue:{seconds:Number.MIN_SAFE_INTEGER}}:"timestampValue"in s?{stringValue:""}:"stringValue"in s?{bytesValue:""}:"bytesValue"in s?r0(rR.empty(),ri.empty()):"referenceValue"in s?{geoPointValue:{latitude:-90,longitude:-180}}:"geoPointValue"in s?{arrayValue:{}}:"arrayValue"in s?{mapValue:{}}:"mapValue"in s?rK:nK(),t=!1;break;case"==":case"in":case"<=":e=n.value;break;case"<":e=n.value,t=!1;break;case"!=":case"not-in":e=rK}r7({value:r,inclusive:i},{value:e,inclusive:t})>0&&(r=e,i=t)}if(null!==n){for(let s=0;s<e.orderBy.length;++s)if(e.orderBy[s].field.isEqual(t)){let e=n.position[s];r7({value:r,inclusive:i},{value:e,inclusive:n.inclusive})>0&&(r=e,i=n.inclusive);break}}return{value:r,inclusive:i}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iV{constructor(e,t=null,n=[],r=[],i=null,s="F",a=null,o=null){this.path=e,this.collectionGroup=t,this.explicitOrderBy=n,this.filters=r,this.limit=i,this.limitType=s,this.startAt=a,this.endAt=o,this.dt=null,this._t=null,this.startAt,this.endAt}}function iq(e){return new iV(e)}function iB(e){return 0===e.filters.length&&null===e.limit&&null==e.startAt&&null==e.endAt&&(0===e.explicitOrderBy.length||1===e.explicitOrderBy.length&&e.explicitOrderBy[0].field.isKeyField())}function ij(e){return e.explicitOrderBy.length>0?e.explicitOrderBy[0].field:null}function iz(e){for(let t of e.filters){let e=t.getFirstInequalityField();if(null!==e)return e}return null}function i$(e){return null!==e.collectionGroup}function iG(e){let t=e;if(null===t.dt){t.dt=[];let e=iz(t),n=ij(t);if(null!==e&&null===n)e.isKeyField()||t.dt.push(new ib(e)),t.dt.push(new ib(rr.keyField(),"asc"));else{let e=!1;for(let n of t.explicitOrderBy)t.dt.push(n),n.field.isKeyField()&&(e=!0);if(!e){let e=t.explicitOrderBy.length>0?t.explicitOrderBy[t.explicitOrderBy.length-1].dir:"asc";t.dt.push(new ib(rr.keyField(),e))}}}return t.dt}function iK(e){let t=e;if(!t._t){if("F"===t.limitType)t._t=iD(t.path,t.collectionGroup,iG(t),t.filters,t.limit,t.startAt,t.endAt);else{let e=[];for(let n of iG(t)){let t="desc"===n.dir?"asc":"desc";e.push(new ib(n.field,t))}let n=t.endAt?new ie(t.endAt.position,t.endAt.inclusive):null,r=t.startAt?new ie(t.startAt.position,t.startAt.inclusive):null;t._t=iD(t.path,t.collectionGroup,e,t.filters,t.limit,n,r)}}return t._t}function iW(e,t){t.getFirstInequalityField(),iz(e);let n=e.filters.concat([t]);return new iV(e.path,e.collectionGroup,e.explicitOrderBy.slice(),n,e.limit,e.limitType,e.startAt,e.endAt)}function iH(e,t,n){return new iV(e.path,e.collectionGroup,e.explicitOrderBy.slice(),e.filters.slice(),t,n,e.startAt,e.endAt)}function iQ(e,t){return iP(iK(e),iK(t))&&e.limitType===t.limitType}function iY(e){return`${iO(iK(e))}|lt:${e.limitType}`}function iX(e){var t;let n;return`Query(target=${n=(t=iK(e)).path.canonicalString(),null!==t.collectionGroup&&(n+=" collectionGroup="+t.collectionGroup),t.filters.length>0&&(n+=`, filters: [${t.filters.map(e=>(function e(t){return t instanceof is?`${t.field.canonicalString()} ${t.op} ${rZ(t.value)}`:t instanceof ia?t.op.toString()+" {"+t.getFilters().map(e).join(" ,")+"}":"Filter"})(e)).join(", ")}]`),rL(t.limit)||(n+=", limit: "+t.limit),t.orderBy.length>0&&(n+=`, orderBy: [${t.orderBy.map(e=>`${e.field.canonicalString()} (${e.dir})`).join(", ")}]`),t.startAt&&(n+=", startAt: "+(t.startAt.inclusive?"b:":"a:")+t.startAt.position.map(e=>rZ(e)).join(",")),t.endAt&&(n+=", endAt: "+(t.endAt.inclusive?"a:":"b:")+t.endAt.position.map(e=>rZ(e)).join(",")),`Target(${n})`}; limitType=${e.limitType})`}function iJ(e,t){return t.isFoundDocument()&&function(e,t){let n=t.key.path;return null!==e.collectionGroup?t.key.hasCollectionId(e.collectionGroup)&&e.path.isPrefixOf(n):ri.isDocumentKey(e.path)?e.path.isEqual(n):e.path.isImmediateParentOf(n)}(e,t)&&function(e,t){for(let n of iG(e))if(!n.field.isKeyField()&&null===t.data.field(n.field))return!1;return!0}(e,t)&&function(e,t){for(let n of e.filters)if(!n.matches(t))return!1;return!0}(e,t)&&(!e.startAt||!!function(e,t,n){let r=it(e,t,n);return e.inclusive?r<=0:r<0}(e.startAt,iG(e),t))&&(!e.endAt||!!function(e,t,n){let r=it(e,t,n);return e.inclusive?r>=0:r>0}(e.endAt,iG(e),t))}function iZ(e){return e.collectionGroup||(e.path.length%2==1?e.path.lastSegment():e.path.get(e.path.length-2))}function i0(e){return(t,n)=>{let r=!1;for(let i of iG(e)){let e=function(e,t,n){let r=e.field.isKeyField()?ri.comparator(t.key,n.key):function(e,t,n){let r=t.data.field(e),i=n.data.field(e);return null!==r&&null!==i?rX(r,i):nK()}(e.field,t,n);switch(e.dir){case"asc":return r;case"desc":return -1*r;default:return nK()}}(i,t,n);if(0!==e)return e;r=r||i.field.isKeyField()}return 0}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function i1(e,t){if(e.wt){if(isNaN(t))return{doubleValue:"NaN"};if(t===1/0)return{doubleValue:"Infinity"};if(t===-1/0)return{doubleValue:"-Infinity"}}return{doubleValue:rM(t)?"-0":t}}function i2(e){return{integerValue:""+e}}function i3(e,t){return rU(t)?i2(t):i1(e,t)}/**
 * @license
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class i4{constructor(){this._=void 0}}function i6(e,t){return e instanceof st?r1(t)||t&&"doubleValue"in t?t:{integerValue:0}:null}class i5 extends i4{}class i9 extends i4{constructor(e){super(),this.elements=e}}function i8(e,t){let n=sr(t);for(let t of e.elements)n.some(e=>rQ(e,t))||n.push(t);return{arrayValue:{values:n}}}class i7 extends i4{constructor(e){super(),this.elements=e}}function se(e,t){let n=sr(t);for(let t of e.elements)n=n.filter(e=>!rQ(e,t));return{arrayValue:{values:n}}}class st extends i4{constructor(e,t){super(),this.yt=e,this.gt=t}}function sn(e){return rj(e.integerValue||e.doubleValue)}function sr(e){return r2(e)&&e.arrayValue.values?e.arrayValue.values.slice():[]}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class si{constructor(e,t){this.field=e,this.transform=t}}class ss{constructor(e,t){this.version=e,this.transformResults=t}}class sa{constructor(e,t){this.updateTime=e,this.exists=t}static none(){return new sa}static exists(e){return new sa(void 0,e)}static updateTime(e){return new sa(e)}get isNone(){return void 0===this.updateTime&&void 0===this.exists}isEqual(e){return this.exists===e.exists&&(this.updateTime?!!e.updateTime&&this.updateTime.isEqual(e.updateTime):!e.updateTime)}}function so(e,t){return void 0!==e.updateTime?t.isFoundDocument()&&t.version.isEqual(e.updateTime):void 0===e.exists||e.exists===t.isFoundDocument()}class sl{}function su(e,t){if(!e.hasLocalMutations||t&&0===t.fields.length)return null;if(null===t)return e.isNoDocument()?new sy(e.key,sa.none()):new sd(e.key,e.data,sa.none());{let n=e.data,r=ix.empty(),i=new iS(rr.comparator);for(let e of t.fields)if(!i.has(e)){let t=n.field(e);null===t&&e.length>1&&(e=e.popLast(),t=n.field(e)),null===t?r.delete(e):r.set(e,t),i=i.add(e)}return new sf(e.key,r,new iC(i.toArray()),sa.none())}}function sc(e,t,n,r){return e instanceof sd?function(e,t,n,r){if(!so(e.precondition,t))return n;let i=e.value.clone(),s=sg(e.fieldTransforms,r,t);return i.setAll(s),t.convertToFoundDocument(t.version,i).setHasLocalMutations(),null}(e,t,n,r):e instanceof sf?function(e,t,n,r){if(!so(e.precondition,t))return n;let i=sg(e.fieldTransforms,r,t),s=t.data;return(s.setAll(sp(e)),s.setAll(i),t.convertToFoundDocument(t.version,s).setHasLocalMutations(),null===n)?null:n.unionWith(e.fieldMask.fields).unionWith(e.fieldTransforms.map(e=>e.field))}(e,t,n,r):so(e.precondition,t)?(t.convertToNoDocument(t.version).setHasLocalMutations(),null):n}function sh(e,t){var n,r;return e.type===t.type&&!!e.key.isEqual(t.key)&&!!e.precondition.isEqual(t.precondition)&&(n=e.fieldTransforms,r=t.fieldTransforms,!!(void 0===n&&void 0===r||!(!n||!r)&&n9(n,r,(e,t)=>{var n,r;return e.field.isEqual(t.field)&&(n=e.transform,r=t.transform,n instanceof i9&&r instanceof i9||n instanceof i7&&r instanceof i7?n9(n.elements,r.elements,rQ):n instanceof st&&r instanceof st?rQ(n.gt,r.gt):n instanceof i5&&r instanceof i5)})))&&(0===e.type?e.value.isEqual(t.value):1!==e.type||e.data.isEqual(t.data)&&e.fieldMask.isEqual(t.fieldMask))}class sd extends sl{constructor(e,t,n,r=[]){super(),this.key=e,this.value=t,this.precondition=n,this.fieldTransforms=r,this.type=0}getFieldMask(){return null}}class sf extends sl{constructor(e,t,n,r,i=[]){super(),this.key=e,this.data=t,this.fieldMask=n,this.precondition=r,this.fieldTransforms=i,this.type=1}getFieldMask(){return this.fieldMask}}function sp(e){let t=new Map;return e.fieldMask.fields.forEach(n=>{if(!n.isEmpty()){let r=e.data.field(n);t.set(n,r)}}),t}function sm(e,t,n){var r;let i=new Map;e.length===n.length||nK();for(let s=0;s<n.length;s++){let a=e[s],o=a.transform,l=t.data.field(a.field);i.set(a.field,(r=n[s],o instanceof i9?i8(o,l):o instanceof i7?se(o,l):r))}return i}function sg(e,t,n){let r=new Map;for(let i of e){let e=i.transform,s=n.data.field(i.field);r.set(i.field,e instanceof i5?function(e,t){let n={fields:{__type__:{stringValue:"server_timestamp"},__local_write_time__:{timestampValue:{seconds:e.seconds,nanos:e.nanoseconds}}}};return t&&(n.fields.__previous_value__=t),{mapValue:n}}(t,s):e instanceof i9?i8(e,s):e instanceof i7?se(e,s):function(e,t){let n=i6(e,t),r=sn(n)+sn(e.gt);return r1(n)&&r1(e.gt)?i2(r):i1(e.yt,r)}(e,s))}return r}class sy extends sl{constructor(e,t){super(),this.key=e,this.precondition=t,this.type=2,this.fieldTransforms=[]}getFieldMask(){return null}}class sv extends sl{constructor(e,t){super(),this.key=e,this.precondition=t,this.type=3,this.fieldTransforms=[]}getFieldMask(){return null}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sw{constructor(e){this.count=e}}function s_(e){switch(e){default:return nK();case nH.CANCELLED:case nH.UNKNOWN:case nH.DEADLINE_EXCEEDED:case nH.RESOURCE_EXHAUSTED:case nH.INTERNAL:case nH.UNAVAILABLE:case nH.UNAUTHENTICATED:return!1;case nH.INVALID_ARGUMENT:case nH.NOT_FOUND:case nH.ALREADY_EXISTS:case nH.PERMISSION_DENIED:case nH.FAILED_PRECONDITION:case nH.ABORTED:case nH.OUT_OF_RANGE:case nH.UNIMPLEMENTED:case nH.DATA_LOSS:return!0}}function sb(e){if(void 0===e)return nz("GRPC error has no .code"),nH.UNKNOWN;switch(e){case l.OK:return nH.OK;case l.CANCELLED:return nH.CANCELLED;case l.UNKNOWN:return nH.UNKNOWN;case l.DEADLINE_EXCEEDED:return nH.DEADLINE_EXCEEDED;case l.RESOURCE_EXHAUSTED:return nH.RESOURCE_EXHAUSTED;case l.INTERNAL:return nH.INTERNAL;case l.UNAVAILABLE:return nH.UNAVAILABLE;case l.UNAUTHENTICATED:return nH.UNAUTHENTICATED;case l.INVALID_ARGUMENT:return nH.INVALID_ARGUMENT;case l.NOT_FOUND:return nH.NOT_FOUND;case l.ALREADY_EXISTS:return nH.ALREADY_EXISTS;case l.PERMISSION_DENIED:return nH.PERMISSION_DENIED;case l.FAILED_PRECONDITION:return nH.FAILED_PRECONDITION;case l.ABORTED:return nH.ABORTED;case l.OUT_OF_RANGE:return nH.OUT_OF_RANGE;case l.UNIMPLEMENTED:return nH.UNIMPLEMENTED;case l.DATA_LOSS:return nH.DATA_LOSS;default:return nK()}}(u=l||(l={}))[u.OK=0]="OK",u[u.CANCELLED=1]="CANCELLED",u[u.UNKNOWN=2]="UNKNOWN",u[u.INVALID_ARGUMENT=3]="INVALID_ARGUMENT",u[u.DEADLINE_EXCEEDED=4]="DEADLINE_EXCEEDED",u[u.NOT_FOUND=5]="NOT_FOUND",u[u.ALREADY_EXISTS=6]="ALREADY_EXISTS",u[u.PERMISSION_DENIED=7]="PERMISSION_DENIED",u[u.UNAUTHENTICATED=16]="UNAUTHENTICATED",u[u.RESOURCE_EXHAUSTED=8]="RESOURCE_EXHAUSTED",u[u.FAILED_PRECONDITION=9]="FAILED_PRECONDITION",u[u.ABORTED=10]="ABORTED",u[u.OUT_OF_RANGE=11]="OUT_OF_RANGE",u[u.UNIMPLEMENTED=12]="UNIMPLEMENTED",u[u.INTERNAL=13]="INTERNAL",u[u.UNAVAILABLE=14]="UNAVAILABLE",u[u.DATA_LOSS=15]="DATA_LOSS";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sI{constructor(e,t){this.mapKeyFn=e,this.equalsFn=t,this.inner={},this.innerSize=0}get(e){let t=this.mapKeyFn(e),n=this.inner[t];if(void 0!==n){for(let[t,r]of n)if(this.equalsFn(t,e))return r}}has(e){return void 0!==this.get(e)}set(e,t){let n=this.mapKeyFn(e),r=this.inner[n];if(void 0===r)return this.inner[n]=[[e,t]],void this.innerSize++;for(let n=0;n<r.length;n++)if(this.equalsFn(r[n][0],e))return void(r[n]=[e,t]);r.push([e,t]),this.innerSize++}delete(e){let t=this.mapKeyFn(e),n=this.inner[t];if(void 0===n)return!1;for(let r=0;r<n.length;r++)if(this.equalsFn(n[r][0],e))return 1===n.length?delete this.inner[t]:n.splice(r,1),this.innerSize--,!0;return!1}forEach(e){rO(this.inner,(t,n)=>{for(let[t,r]of n)e(t,r)})}isEmpty(){return rP(this.inner)}size(){return this.innerSize}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let sT=new iI(ri.comparator),sE=new iI(ri.comparator);function sS(...e){let t=sE;for(let n of e)t=t.insert(n.key,n);return t}function sk(e){let t=sE;return e.forEach((e,n)=>t=t.insert(e,n.overlayedDocument)),t}function sA(){return new sI(e=>e.toString(),(e,t)=>e.isEqual(t))}let sC=new iI(ri.comparator),sx=new iS(ri.comparator);function sN(...e){let t=sx;for(let n of e)t=t.add(n);return t}let sR=new iS(n5);/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sD{constructor(e,t,n,r,i){this.snapshotVersion=e,this.targetChanges=t,this.targetMismatches=n,this.documentUpdates=r,this.resolvedLimboDocuments=i}static createSynthesizedRemoteEventForCurrentChange(e,t,n){let r=new Map;return r.set(e,sO.createSynthesizedTargetChangeForCurrentChange(e,t,n)),new sD(n7.min(),r,sR,sT,sN())}}class sO{constructor(e,t,n,r,i){this.resumeToken=e,this.current=t,this.addedDocuments=n,this.modifiedDocuments=r,this.removedDocuments=i}static createSynthesizedTargetChangeForCurrentChange(e,t,n){return new sO(n,t,sN(),sN(),sN())}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sP{constructor(e,t,n,r){this.It=e,this.removedTargetIds=t,this.key=n,this.Tt=r}}class sL{constructor(e,t){this.targetId=e,this.Et=t}}class sM{constructor(e,t,n=rV.EMPTY_BYTE_STRING,r=null){this.state=e,this.targetIds=t,this.resumeToken=n,this.cause=r}}class sU{constructor(){this.At=0,this.Rt=sq(),this.bt=rV.EMPTY_BYTE_STRING,this.Pt=!1,this.vt=!0}get current(){return this.Pt}get resumeToken(){return this.bt}get Vt(){return 0!==this.At}get St(){return this.vt}Dt(e){e.approximateByteSize()>0&&(this.vt=!0,this.bt=e)}Ct(){let e=sN(),t=sN(),n=sN();return this.Rt.forEach((r,i)=>{switch(i){case 0:e=e.add(r);break;case 2:t=t.add(r);break;case 1:n=n.add(r);break;default:nK()}}),new sO(this.bt,this.Pt,e,t,n)}xt(){this.vt=!1,this.Rt=sq()}Nt(e,t){this.vt=!0,this.Rt=this.Rt.insert(e,t)}kt(e){this.vt=!0,this.Rt=this.Rt.remove(e)}Ot(){this.At+=1}Mt(){this.At-=1}Ft(){this.vt=!0,this.Pt=!0}}class sF{constructor(e){this.$t=e,this.Bt=new Map,this.Lt=sT,this.qt=sV(),this.Ut=new iS(n5)}Kt(e){for(let t of e.It)e.Tt&&e.Tt.isFoundDocument()?this.Gt(t,e.Tt):this.Qt(t,e.key,e.Tt);for(let t of e.removedTargetIds)this.Qt(t,e.key,e.Tt)}jt(e){this.forEachTarget(e,t=>{let n=this.Wt(t);switch(e.state){case 0:this.zt(t)&&n.Dt(e.resumeToken);break;case 1:n.Mt(),n.Vt||n.xt(),n.Dt(e.resumeToken);break;case 2:n.Mt(),n.Vt||this.removeTarget(t);break;case 3:this.zt(t)&&(n.Ft(),n.Dt(e.resumeToken));break;case 4:this.zt(t)&&(this.Ht(t),n.Dt(e.resumeToken));break;default:nK()}})}forEachTarget(e,t){e.targetIds.length>0?e.targetIds.forEach(t):this.Bt.forEach((e,n)=>{this.zt(n)&&t(n)})}Jt(e){let t=e.targetId,n=e.Et.count,r=this.Yt(t);if(r){let e=r.target;if(iL(e)){if(0===n){let n=new ri(e.path);this.Qt(t,n,iN.newNoDocument(n,n7.min()))}else 1===n||nK()}else this.Xt(t)!==n&&(this.Ht(t),this.Ut=this.Ut.add(t))}}Zt(e){let t=new Map;this.Bt.forEach((n,r)=>{let i=this.Yt(r);if(i){if(n.current&&iL(i.target)){let t=new ri(i.target.path);null!==this.Lt.get(t)||this.te(r,t)||this.Qt(r,t,iN.newNoDocument(t,e))}n.St&&(t.set(r,n.Ct()),n.xt())}});let n=sN();this.qt.forEach((e,t)=>{let r=!0;t.forEachWhile(e=>{let t=this.Yt(e);return!t||2===t.purpose||(r=!1,!1)}),r&&(n=n.add(e))}),this.Lt.forEach((t,n)=>n.setReadTime(e));let r=new sD(e,t,this.Ut,this.Lt,n);return this.Lt=sT,this.qt=sV(),this.Ut=new iS(n5),r}Gt(e,t){if(!this.zt(e))return;let n=this.te(e,t.key)?2:0;this.Wt(e).Nt(t.key,n),this.Lt=this.Lt.insert(t.key,t),this.qt=this.qt.insert(t.key,this.ee(t.key).add(e))}Qt(e,t,n){if(!this.zt(e))return;let r=this.Wt(e);this.te(e,t)?r.Nt(t,1):r.kt(t),this.qt=this.qt.insert(t,this.ee(t).delete(e)),n&&(this.Lt=this.Lt.insert(t,n))}removeTarget(e){this.Bt.delete(e)}Xt(e){let t=this.Wt(e).Ct();return this.$t.getRemoteKeysForTarget(e).size+t.addedDocuments.size-t.removedDocuments.size}Ot(e){this.Wt(e).Ot()}Wt(e){let t=this.Bt.get(e);return t||(t=new sU,this.Bt.set(e,t)),t}ee(e){let t=this.qt.get(e);return t||(t=new iS(n5),this.qt=this.qt.insert(e,t)),t}zt(e){let t=null!==this.Yt(e);return t||nj("WatchChangeAggregator","Detected inactive target",e),t}Yt(e){let t=this.Bt.get(e);return t&&t.Vt?null:this.$t.ne(e)}Ht(e){this.Bt.set(e,new sU),this.$t.getRemoteKeysForTarget(e).forEach(t=>{this.Qt(e,t,null)})}te(e,t){return this.$t.getRemoteKeysForTarget(e).has(t)}}function sV(){return new iI(ri.comparator)}function sq(){return new iI(ri.comparator)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let sB={asc:"ASCENDING",desc:"DESCENDING"},sj={"<":"LESS_THAN","<=":"LESS_THAN_OR_EQUAL",">":"GREATER_THAN",">=":"GREATER_THAN_OR_EQUAL","==":"EQUAL","!=":"NOT_EQUAL","array-contains":"ARRAY_CONTAINS",in:"IN","not-in":"NOT_IN","array-contains-any":"ARRAY_CONTAINS_ANY"},sz={and:"AND",or:"OR"};class s${constructor(e,t){this.databaseId=e,this.wt=t}}function sG(e,t){return e.wt?`${new Date(1e3*t.seconds).toISOString().replace(/\.\d*/,"").replace("Z","")}.${("000000000"+t.nanoseconds).slice(-9)}Z`:{seconds:""+t.seconds,nanos:t.nanoseconds}}function sK(e,t){return e.wt?t.toBase64():t.toUint8Array()}function sW(e){return e||nK(),n7.fromTimestamp(function(e){let t=rB(e);return new n8(t.seconds,t.nanos)}(e))}function sH(e,t){return new rt(["projects",e.projectId,"databases",e.database]).child("documents").child(t).canonicalString()}function sQ(e){let t=rt.fromString(e);return at(t)||nK(),t}function sY(e,t){return sH(e.databaseId,t.path)}function sX(e,t){let n=sQ(t);if(n.get(1)!==e.databaseId.projectId)throw new nQ(nH.INVALID_ARGUMENT,"Tried to deserialize key from different project: "+n.get(1)+" vs "+e.databaseId.projectId);if(n.get(3)!==e.databaseId.database)throw new nQ(nH.INVALID_ARGUMENT,"Tried to deserialize key from different database: "+n.get(3)+" vs "+e.databaseId.database);return new ri(s1(n))}function sJ(e,t){return sH(e.databaseId,t)}function sZ(e){let t=sQ(e);return 4===t.length?rt.emptyPath():s1(t)}function s0(e){return new rt(["projects",e.databaseId.projectId,"databases",e.databaseId.database]).canonicalString()}function s1(e){return e.length>4&&"documents"===e.get(4)||nK(),e.popFirst(5)}function s2(e,t,n){return{name:sY(e,t),fields:n.value.mapValue.fields}}function s3(e,t,n){let r=sX(e,t.name),i=sW(t.updateTime),s=t.createTime?sW(t.createTime):n7.min(),a=new ix({mapValue:{fields:t.fields}}),o=iN.newFoundDocument(r,i,s,a);return n&&o.setHasCommittedMutations(),n?o.setHasCommittedMutations():o}function s4(e,t){var n;let r;if(t instanceof sd)r={update:s2(e,t.key,t.value)};else if(t instanceof sy)r={delete:sY(e,t.key)};else if(t instanceof sf)r={update:s2(e,t.key,t.data),updateMask:function(e){let t=[];return e.fields.forEach(e=>t.push(e.canonicalString())),{fieldPaths:t}}(t.fieldMask)};else{if(!(t instanceof sv))return nK();r={verify:sY(e,t.key)}}return t.fieldTransforms.length>0&&(r.updateTransforms=t.fieldTransforms.map(e=>(function(e,t){let n=t.transform;if(n instanceof i5)return{fieldPath:t.field.canonicalString(),setToServerValue:"REQUEST_TIME"};if(n instanceof i9)return{fieldPath:t.field.canonicalString(),appendMissingElements:{values:n.elements}};if(n instanceof i7)return{fieldPath:t.field.canonicalString(),removeAllFromArray:{values:n.elements}};if(n instanceof st)return{fieldPath:t.field.canonicalString(),increment:n.gt};throw nK()})(0,e))),t.precondition.isNone||(r.currentDocument=void 0!==(n=t.precondition).updateTime?{updateTime:sG(e,n.updateTime.toTimestamp())}:void 0!==n.exists?{exists:n.exists}:nK()),r}function s6(e,t){var n;let r=t.currentDocument?void 0!==(n=t.currentDocument).updateTime?sa.updateTime(sW(n.updateTime)):void 0!==n.exists?sa.exists(n.exists):sa.none():sa.none(),i=t.updateTransforms?t.updateTransforms.map(t=>(function(e,t){let n=null;if("setToServerValue"in t)"REQUEST_TIME"===t.setToServerValue||nK(),n=new i5;else if("appendMissingElements"in t){let e=t.appendMissingElements.values||[];n=new i9(e)}else if("removeAllFromArray"in t){let e=t.removeAllFromArray.values||[];n=new i7(e)}else"increment"in t?n=new st(e,t.increment):nK();let r=rr.fromServerFormat(t.fieldPath);return new si(r,n)})(e,t)):[];if(t.update){t.update.name;let n=sX(e,t.update.name),s=new ix({mapValue:{fields:t.update.fields}});if(t.updateMask){let e=function(e){let t=e.fieldPaths||[];return new iC(t.map(e=>rr.fromServerFormat(e)))}(t.updateMask);return new sf(n,s,e,r,i)}return new sd(n,s,r,i)}if(t.delete){let n=sX(e,t.delete);return new sy(n,r)}if(t.verify){let n=sX(e,t.verify);return new sv(n,r)}return nK()}function s5(e,t){return{documents:[sJ(e,t.path)]}}function s9(e,t){var n,r,i;let s={structuredQuery:{}},a=t.path;null!==t.collectionGroup?(s.parent=sJ(e,a),s.structuredQuery.from=[{collectionId:t.collectionGroup,allDescendants:!0}]):(s.parent=sJ(e,a.popLast()),s.structuredQuery.from=[{collectionId:a.lastSegment()}]);let o=function(e){if(0!==e.length)return function e(t){return t instanceof is?function(e){if("=="===e.op){if(r4(e.value))return{unaryFilter:{field:s7(e.field),op:"IS_NAN"}};if(r3(e.value))return{unaryFilter:{field:s7(e.field),op:"IS_NULL"}}}else if("!="===e.op){if(r4(e.value))return{unaryFilter:{field:s7(e.field),op:"IS_NOT_NAN"}};if(r3(e.value))return{unaryFilter:{field:s7(e.field),op:"IS_NOT_NULL"}}}return{fieldFilter:{field:s7(e.field),op:sj[e.op],value:e.value}}}(t):t instanceof ia?function(t){let n=t.getFilters().map(t=>e(t));return 1===n.length?n[0]:{compositeFilter:{op:sz[t.op],filters:n}}}(t):nK()}(ia.create(e,"and"))}(t.filters);o&&(s.structuredQuery.where=o);let l=function(e){if(0!==e.length)return e.map(e=>({field:s7(e.field),direction:sB[e.dir]}))}(t.orderBy);l&&(s.structuredQuery.orderBy=l);let u=(r=t.limit,e.wt||rL(r)?r:{value:r});return null!==u&&(s.structuredQuery.limit=u),t.startAt&&(s.structuredQuery.startAt={before:(n=t.startAt).inclusive,values:n.position}),t.endAt&&(s.structuredQuery.endAt={before:!(i=t.endAt).inclusive,values:i.position}),s}function s8(e){var t,n,r,i,s,a,o,l;let u,c=sZ(e.parent),h=e.structuredQuery,d=h.from?h.from.length:0,f=null;if(d>0){1===d||nK();let e=h.from[0];e.allDescendants?f=e.collectionId:c=c.child(e.collectionId)}let p=[];h.where&&(p=function(e){let t=function e(t){return void 0!==t.unaryFilter?function(e){switch(e.unaryFilter.op){case"IS_NAN":let t=ae(e.unaryFilter.field);return is.create(t,"==",{doubleValue:NaN});case"IS_NULL":let n=ae(e.unaryFilter.field);return is.create(n,"==",{nullValue:"NULL_VALUE"});case"IS_NOT_NAN":let r=ae(e.unaryFilter.field);return is.create(r,"!=",{doubleValue:NaN});case"IS_NOT_NULL":let i=ae(e.unaryFilter.field);return is.create(i,"!=",{nullValue:"NULL_VALUE"});default:return nK()}}(t):void 0!==t.fieldFilter?is.create(ae(t.fieldFilter.field),function(e){switch(e){case"EQUAL":return"==";case"NOT_EQUAL":return"!=";case"GREATER_THAN":return">";case"GREATER_THAN_OR_EQUAL":return">=";case"LESS_THAN":return"<";case"LESS_THAN_OR_EQUAL":return"<=";case"ARRAY_CONTAINS":return"array-contains";case"IN":return"in";case"NOT_IN":return"not-in";case"ARRAY_CONTAINS_ANY":return"array-contains-any";default:return nK()}}(t.fieldFilter.op),t.fieldFilter.value):void 0!==t.compositeFilter?ia.create(t.compositeFilter.filters.map(t=>e(t)),function(e){switch(e){case"AND":return"and";case"OR":return"or";default:return nK()}}(t.compositeFilter.op)):nK()}(e);return t instanceof ia&&iu(t)?t.getFilters():[t]}(h.where));let m=[];h.orderBy&&(m=h.orderBy.map(e=>new ib(ae(e.field),function(e){switch(e){case"ASCENDING":return"asc";case"DESCENDING":return"desc";default:return}}(e.direction))));let g=null;h.limit&&(g=rL(u="object"==typeof(t=h.limit)?t.value:t)?null:u);let y=null;h.startAt&&(y=function(e){let t=!!e.before,n=e.values||[];return new ie(n,t)}(h.startAt));let v=null;return h.endAt&&(v=function(e){let t=!e.before,n=e.values||[];return new ie(n,t)}(h.endAt)),n=c,r=f,i=m,s=p,a=g,o=y,l=v,new iV(n,r,i,s,a,"F",o,l)}function s7(e){return{fieldPath:e.canonicalString()}}function ae(e){return rr.fromServerFormat(e.fieldPath)}function at(e){return e.length>=4&&"projects"===e.get(0)&&"databases"===e.get(2)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function an(e){var t,n;let r="";for(let t=0;t<e.length;t++)r.length>0&&(r+="\x01\x01"),r=function(e,t){let n=t,r=e.length;for(let t=0;t<r;t++){let r=e.charAt(t);switch(r){case"\x00":n+="\x01\x10";break;case"\x01":n+="\x01\x11";break;default:n+=r}}return n}(e.get(t),r);return r+"\x01\x01"}function ar(e){let t=e.length;if(t>=2||nK(),2===t)return"\x01"===e.charAt(0)&&"\x01"===e.charAt(1)||nK(),rt.emptyPath();let n=t-2,r=[],i="";for(let s=0;s<t;){let t=e.indexOf("\x01",s);switch((t<0||t>n)&&nK(),e.charAt(t+1)){case"\x01":let a;let o=e.substring(s,t);0===i.length?a=o:(i+=o,a=i,i=""),r.push(a);break;case"\x10":i+=e.substring(s,t)+"\x00";break;case"\x11":i+=e.substring(s,t+1);break;default:nK()}s=t+2}return new rt(r)}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ai=["userId","batchId"],as={},aa=["prefixPath","collectionGroup","readTime","documentId"],ao=["prefixPath","collectionGroup","documentId"],al=["collectionGroup","readTime","prefixPath","documentId"],au=["canonicalId","targetId"],ac=["targetId","path"],ah=["path","targetId"],ad=["collectionId","parent"],af=["indexId","uid"],ap=["uid","sequenceNumber"],am=["indexId","uid","arrayValue","directionalValue","orderedDocumentKey","documentKey"],ag=["indexId","uid","orderedDocumentKey"],ay=["userId","collectionPath","documentId"],av=["userId","collectionPath","largestBatchId"],aw=["userId","collectionGroup","largestBatchId"],a_=["mutationQueues","mutations","documentMutations","remoteDocuments","targets","owner","targetGlobal","targetDocuments","clientMetadata","remoteDocumentGlobal","collectionParents","bundles","namedQueries"],ab=[...a_,"documentOverlays"],aI=["mutationQueues","mutations","documentMutations","remoteDocumentsV14","targets","owner","targetGlobal","targetDocuments","clientMetadata","remoteDocumentGlobal","collectionParents","bundles","namedQueries","documentOverlays"],aT=[...aI,"indexConfiguration","indexState","indexEntries"];/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aE extends rm{constructor(e,t){super(),this.se=e,this.currentSequenceNumber=t}}function aS(e,t){return rw.M(e.se,t)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ak{constructor(e,t,n,r){this.batchId=e,this.localWriteTime=t,this.baseMutations=n,this.mutations=r}applyToRemoteDocument(e,t){let n=t.mutationResults;for(let t=0;t<this.mutations.length;t++){let i=this.mutations[t];if(i.key.isEqual(e.key)){var r;r=n[t],i instanceof sd?function(e,t,n){let r=e.value.clone(),i=sm(e.fieldTransforms,t,n.transformResults);r.setAll(i),t.convertToFoundDocument(n.version,r).setHasCommittedMutations()}(i,e,r):i instanceof sf?function(e,t,n){if(!so(e.precondition,t))return void t.convertToUnknownDocument(n.version);let r=sm(e.fieldTransforms,t,n.transformResults),i=t.data;i.setAll(sp(e)),i.setAll(r),t.convertToFoundDocument(n.version,i).setHasCommittedMutations()}(i,e,r):function(e,t,n){t.convertToNoDocument(n.version).setHasCommittedMutations()}(0,e,r)}}}applyToLocalView(e,t){for(let n of this.baseMutations)n.key.isEqual(e.key)&&(t=sc(n,e,t,this.localWriteTime));for(let n of this.mutations)n.key.isEqual(e.key)&&(t=sc(n,e,t,this.localWriteTime));return t}applyToLocalDocumentSet(e,t){let n=sA();return this.mutations.forEach(r=>{let i=e.get(r.key),s=i.overlayedDocument,a=this.applyToLocalView(s,i.mutatedFields);a=t.has(r.key)?null:a;let o=su(s,a);null!==o&&n.set(r.key,o),s.isValidDocument()||s.convertToNoDocument(n7.min())}),n}keys(){return this.mutations.reduce((e,t)=>e.add(t.key),sN())}isEqual(e){return this.batchId===e.batchId&&n9(this.mutations,e.mutations,(e,t)=>sh(e,t))&&n9(this.baseMutations,e.baseMutations,(e,t)=>sh(e,t))}}class aA{constructor(e,t,n,r){this.batch=e,this.commitVersion=t,this.mutationResults=n,this.docVersions=r}static from(e,t,n){e.mutations.length===n.length||nK();let r=sC,i=e.mutations;for(let e=0;e<i.length;e++)r=r.insert(i[e].key,n[e].version);return new aA(e,t,n,r)}}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aC{constructor(e,t){this.largestBatchId=e,this.mutation=t}getKey(){return this.mutation.key}isEqual(e){return null!==e&&this.mutation===e.mutation}toString(){return`Overlay{
      largestBatchId: ${this.largestBatchId},
      mutation: ${this.mutation.toString()}
    }`}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ax{constructor(e,t,n,r,i=n7.min(),s=n7.min(),a=rV.EMPTY_BYTE_STRING){this.target=e,this.targetId=t,this.purpose=n,this.sequenceNumber=r,this.snapshotVersion=i,this.lastLimboFreeSnapshotVersion=s,this.resumeToken=a}withSequenceNumber(e){return new ax(this.target,this.targetId,this.purpose,e,this.snapshotVersion,this.lastLimboFreeSnapshotVersion,this.resumeToken)}withResumeToken(e,t){return new ax(this.target,this.targetId,this.purpose,this.sequenceNumber,t,this.lastLimboFreeSnapshotVersion,e)}withLastLimboFreeSnapshotVersion(e){return new ax(this.target,this.targetId,this.purpose,this.sequenceNumber,this.snapshotVersion,e,this.resumeToken)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aN{constructor(e){this.ie=e}}function aR(e,t){let n=t.key,r={prefixPath:n.getCollectionPath().popLast().toArray(),collectionGroup:n.collectionGroup,documentId:n.path.lastSegment(),readTime:aD(t.readTime),hasCommittedMutations:t.hasCommittedMutations};if(t.isFoundDocument()){var i;r.document={name:sY(i=e.ie,t.key),fields:t.data.value.mapValue.fields,updateTime:sG(i,t.version.toTimestamp()),createTime:sG(i,t.createTime.toTimestamp())}}else if(t.isNoDocument())r.noDocument={path:n.path.toArray(),readTime:aO(t.version)};else{if(!t.isUnknownDocument())return nK();r.unknownDocument={path:n.path.toArray(),version:aO(t.version)}}return r}function aD(e){let t=e.toTimestamp();return[t.seconds,t.nanoseconds]}function aO(e){let t=e.toTimestamp();return{seconds:t.seconds,nanoseconds:t.nanoseconds}}function aP(e){let t=new n8(e.seconds,e.nanoseconds);return n7.fromTimestamp(t)}function aL(e,t){let n=(t.baseMutations||[]).map(t=>s6(e.ie,t));for(let e=0;e<t.mutations.length-1;++e){let n=t.mutations[e];if(e+1<t.mutations.length&&void 0!==t.mutations[e+1].transform){let r=t.mutations[e+1];n.updateTransforms=r.transform.fieldTransforms,t.mutations.splice(e+1,1),++e}}let r=t.mutations.map(t=>s6(e.ie,t)),i=n8.fromMillis(t.localWriteTimeMs);return new ak(t.batchId,i,n,r)}function aM(e){var t;let n;let r=aP(e.readTime),i=void 0!==e.lastLimboFreeSnapshotVersion?aP(e.lastLimboFreeSnapshotVersion):n7.min();return void 0!==e.query.documents?(1===(t=e.query).documents.length||nK(),n=iK(iq(sZ(t.documents[0])))):n=iK(s8(e.query)),new ax(n,e.targetId,0,e.lastListenSequenceNumber,r,i,rV.fromBase64String(e.resumeToken))}function aU(e,t){let n;let r=aO(t.snapshotVersion),i=aO(t.lastLimboFreeSnapshotVersion);n=iL(t.target)?s5(e.ie,t.target):s9(e.ie,t.target);let s=t.resumeToken.toBase64();return{targetId:t.targetId,canonicalId:iO(t.target),readTime:r,resumeToken:s,lastListenSequenceNumber:t.sequenceNumber,lastLimboFreeSnapshotVersion:i,query:n}}function aF(e){let t=s8({parent:e.parent,structuredQuery:e.structuredQuery});return"LAST"===e.limitType?iH(t,t.limit,"L"):t}function aV(e,t){return new aC(t.largestBatchId,s6(e.ie,t.overlayMutation))}function aq(e,t){let n=t.path.lastSegment();return[e,an(t.path.popLast()),n]}function aB(e,t,n,r){return{indexId:e,uid:t.uid||"",sequenceNumber:n,readTime:aO(r.readTime),documentKey:an(r.documentKey.path),largestBatchId:r.largestBatchId}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aj{getBundleMetadata(e,t){return az(e).get(t).next(e=>{if(e)return{id:e.bundleId,createTime:aP(e.createTime),version:e.version}})}saveBundleMetadata(e,t){return az(e).put({bundleId:t.id,createTime:aO(sW(t.createTime)),version:t.version})}getNamedQuery(e,t){return a$(e).get(t).next(e=>{if(e)return{name:e.name,query:aF(e.bundledQuery),readTime:aP(e.readTime)}})}saveNamedQuery(e,t){return a$(e).put({name:t.name,readTime:aO(sW(t.readTime)),bundledQuery:t.bundledQuery})}}function az(e){return aS(e,"bundles")}function a$(e){return aS(e,"namedQueries")}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aG{constructor(e,t){this.yt=e,this.userId=t}static re(e,t){let n=t.uid||"";return new aG(e,n)}getOverlay(e,t){return aK(e).get(aq(this.userId,t)).next(e=>e?aV(this.yt,e):null)}getOverlays(e,t){let n=sA();return ry.forEach(t,t=>this.getOverlay(e,t).next(e=>{null!==e&&n.set(t,e)})).next(()=>n)}saveOverlays(e,t,n){let r=[];return n.forEach((n,i)=>{let s=new aC(t,i);r.push(this.oe(e,s))}),ry.waitFor(r)}removeOverlaysForBatchId(e,t,n){let r=new Set;t.forEach(e=>r.add(an(e.getCollectionPath())));let i=[];return r.forEach(t=>{let r=IDBKeyRange.bound([this.userId,t,n],[this.userId,t,n+1],!1,!0);i.push(aK(e).Y("collectionPathOverlayIndex",r))}),ry.waitFor(i)}getOverlaysForCollection(e,t,n){let r=sA(),i=an(t),s=IDBKeyRange.bound([this.userId,i,n],[this.userId,i,Number.POSITIVE_INFINITY],!0);return aK(e).W("collectionPathOverlayIndex",s).next(e=>{for(let t of e){let e=aV(this.yt,t);r.set(e.getKey(),e)}return r})}getOverlaysForCollectionGroup(e,t,n,r){let i;let s=sA(),a=IDBKeyRange.bound([this.userId,t,n],[this.userId,t,Number.POSITIVE_INFINITY],!0);return aK(e).Z({index:"collectionGroupOverlayIndex",range:a},(e,t,n)=>{let a=aV(this.yt,t);s.size()<r||a.largestBatchId===i?(s.set(a.getKey(),a),i=a.largestBatchId):n.done()}).next(()=>s)}oe(e,t){return aK(e).put(function(e,t,n){let[r,i,s]=aq(t,n.mutation.key);return{userId:t,collectionPath:i,documentId:s,collectionGroup:n.mutation.key.getCollectionGroup(),largestBatchId:n.largestBatchId,overlayMutation:s4(e.ie,n.mutation)}}(this.yt,this.userId,t))}}function aK(e){return aS(e,"documentOverlays")}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aW{constructor(){}ue(e,t){this.ce(e,t),t.ae()}ce(e,t){if("nullValue"in e)this.he(t,5);else if("booleanValue"in e)this.he(t,10),t.le(e.booleanValue?1:0);else if("integerValue"in e)this.he(t,15),t.le(rj(e.integerValue));else if("doubleValue"in e){let n=rj(e.doubleValue);isNaN(n)?this.he(t,13):(this.he(t,15),rM(n)?t.le(0):t.le(n))}else if("timestampValue"in e){let n=e.timestampValue;this.he(t,20),"string"==typeof n?t.fe(n):(t.fe(`${n.seconds||""}`),t.le(n.nanos||0))}else if("stringValue"in e)this.de(e.stringValue,t),this._e(t);else if("bytesValue"in e)this.he(t,30),t.we(rz(e.bytesValue)),this._e(t);else if("referenceValue"in e)this.me(e.referenceValue,t);else if("geoPointValue"in e){let n=e.geoPointValue;this.he(t,45),t.le(n.latitude||0),t.le(n.longitude||0)}else"mapValue"in e?r9(e)?this.he(t,Number.MAX_SAFE_INTEGER):(this.ge(e.mapValue,t),this._e(t)):"arrayValue"in e?(this.ye(e.arrayValue,t),this._e(t)):nK()}de(e,t){this.he(t,25),this.pe(e,t)}pe(e,t){t.fe(e)}ge(e,t){let n=e.fields||{};for(let e of(this.he(t,55),Object.keys(n)))this.de(e,t),this.ce(n[e],t)}ye(e,t){let n=e.values||[];for(let e of(this.he(t,50),n))this.ce(e,t)}me(e,t){this.he(t,37),ri.fromName(e).path.forEach(e=>{this.he(t,60),this.pe(e,t)})}he(e,t){e.le(t)}_e(e){e.le(2)}}function aH(e){let t=64-function(e){let t=0;for(let n=0;n<8;++n){let r=function(e){if(0===e)return 8;let t=0;return e>>4==0&&(t+=4,e<<=4),e>>6==0&&(t+=2,e<<=2),e>>7==0&&(t+=1),t}(255&e[n]);if(t+=r,8!==r)break}return t}(e);return Math.ceil(t/8)}aW.Ie=new aW;class aQ{constructor(){this.buffer=new Uint8Array(1024),this.position=0}Te(e){let t=e[Symbol.iterator](),n=t.next();for(;!n.done;)this.Ee(n.value),n=t.next();this.Ae()}Re(e){let t=e[Symbol.iterator](),n=t.next();for(;!n.done;)this.be(n.value),n=t.next();this.Pe()}ve(e){for(let t of e){let e=t.charCodeAt(0);if(e<128)this.Ee(e);else if(e<2048)this.Ee(960|e>>>6),this.Ee(128|63&e);else if(t<"\ud800"||"\udbff"<t)this.Ee(480|e>>>12),this.Ee(128|63&e>>>6),this.Ee(128|63&e);else{let e=t.codePointAt(0);this.Ee(240|e>>>18),this.Ee(128|63&e>>>12),this.Ee(128|63&e>>>6),this.Ee(128|63&e)}}this.Ae()}Ve(e){for(let t of e){let e=t.charCodeAt(0);if(e<128)this.be(e);else if(e<2048)this.be(960|e>>>6),this.be(128|63&e);else if(t<"\ud800"||"\udbff"<t)this.be(480|e>>>12),this.be(128|63&e>>>6),this.be(128|63&e);else{let e=t.codePointAt(0);this.be(240|e>>>18),this.be(128|63&e>>>12),this.be(128|63&e>>>6),this.be(128|63&e)}}this.Pe()}Se(e){let t=this.De(e),n=aH(t);this.Ce(1+n),this.buffer[this.position++]=255&n;for(let e=t.length-n;e<t.length;++e)this.buffer[this.position++]=255&t[e]}xe(e){let t=this.De(e),n=aH(t);this.Ce(1+n),this.buffer[this.position++]=~(255&n);for(let e=t.length-n;e<t.length;++e)this.buffer[this.position++]=~(255&t[e])}Ne(){this.ke(255),this.ke(255)}Oe(){this.Me(255),this.Me(255)}reset(){this.position=0}seed(e){this.Ce(e.length),this.buffer.set(e,this.position),this.position+=e.length}Fe(){return this.buffer.slice(0,this.position)}De(e){let t=function(e){let t=new DataView(new ArrayBuffer(8));return t.setFloat64(0,e,!1),new Uint8Array(t.buffer)}(e),n=0!=(128&t[0]);t[0]^=n?255:128;for(let e=1;e<t.length;++e)t[e]^=n?255:0;return t}Ee(e){let t=255&e;0===t?(this.ke(0),this.ke(255)):255===t?(this.ke(255),this.ke(0)):this.ke(t)}be(e){let t=255&e;0===t?(this.Me(0),this.Me(255)):255===t?(this.Me(255),this.Me(0)):this.Me(e)}Ae(){this.ke(0),this.ke(1)}Pe(){this.Me(0),this.Me(1)}ke(e){this.Ce(1),this.buffer[this.position++]=e}Me(e){this.Ce(1),this.buffer[this.position++]=~e}Ce(e){let t=e+this.position;if(t<=this.buffer.length)return;let n=2*this.buffer.length;n<t&&(n=t);let r=new Uint8Array(n);r.set(this.buffer),this.buffer=r}}class aY{constructor(e){this.$e=e}we(e){this.$e.Te(e)}fe(e){this.$e.ve(e)}le(e){this.$e.Se(e)}ae(){this.$e.Ne()}}class aX{constructor(e){this.$e=e}we(e){this.$e.Re(e)}fe(e){this.$e.Ve(e)}le(e){this.$e.xe(e)}ae(){this.$e.Oe()}}class aJ{constructor(){this.$e=new aQ,this.Be=new aY(this.$e),this.Le=new aX(this.$e)}seed(e){this.$e.seed(e)}qe(e){return 0===e?this.Be:this.Le}Fe(){return this.$e.Fe()}reset(){this.$e.reset()}}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aZ{constructor(e,t,n,r){this.indexId=e,this.documentKey=t,this.arrayValue=n,this.directionalValue=r}Ue(){let e=this.directionalValue.length,t=0===e||255===this.directionalValue[e-1]?e+1:e,n=new Uint8Array(t);return n.set(this.directionalValue,0),t!==e?n.set([0],this.directionalValue.length):++n[n.length-1],new aZ(this.indexId,this.documentKey,this.arrayValue,n)}}function a0(e,t){let n=e.indexId-t.indexId;return 0!==n?n:0!==(n=a1(e.arrayValue,t.arrayValue))?n:0!==(n=a1(e.directionalValue,t.directionalValue))?n:ri.comparator(e.documentKey,t.documentKey)}function a1(e,t){for(let n=0;n<e.length&&n<t.length;++n){let r=e[n]-t[n];if(0!==r)return r}return e.length-t.length}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class a2{constructor(e){for(let t of(this.collectionId=null!=e.collectionGroup?e.collectionGroup:e.path.lastSegment(),this.Ke=e.orderBy,this.Ge=[],e.filters)){let e=t;e.isInequality()?this.Qe=e:this.Ge.push(e)}}je(e){e.collectionGroup===this.collectionId||nK();let t=ra(e);if(void 0!==t&&!this.We(t))return!1;let n=ro(e),r=0,i=0;for(;r<n.length&&this.We(n[r]);++r);if(r===n.length)return!0;if(void 0!==this.Qe){let e=n[r];if(!this.ze(this.Qe,e)||!this.He(this.Ke[i++],e))return!1;++r}for(;r<n.length;++r){let e=n[r];if(i>=this.Ke.length||!this.He(this.Ke[i++],e))return!1}return!0}We(e){for(let t of this.Ge)if(this.ze(t,e))return!0;return!1}ze(e,t){if(void 0===e||!e.field.isEqual(t.fieldPath))return!1;let n="array-contains"===e.op||"array-contains-any"===e.op;return 2===t.kind===n}He(e,t){return!!e.field.isEqual(t.fieldPath)&&(0===t.kind&&"asc"===e.dir||1===t.kind&&"desc"===e.dir)}}function a3(e){return e instanceof is}function a4(e){return e instanceof ia&&iu(e)}function a6(e){return a3(e)||a4(e)||function(e){if(e instanceof ia&&il(e)){for(let t of e.getFilters())if(!a3(t)&&!a4(t))return!1;return!0}return!1}(e)}function a5(e,t){return e instanceof is||e instanceof ia||nK(),t instanceof is||t instanceof ia||nK(),a8(e instanceof is?t instanceof is?ia.create([e,t],"and"):a9(e,t):t instanceof is?a9(t,e):function(e,t){if(e.filters.length>0&&t.filters.length>0||nK(),io(e)&&io(t))return ih(e,t.getFilters());let n=il(e)?e:t,r=il(e)?t:e,i=n.filters.map(e=>a5(e,r));return ia.create(i,"or")}(e,t))}function a9(e,t){if(io(t))return ih(t,e.getFilters());{let n=t.filters.map(t=>a5(e,t));return ia.create(n,"or")}}function a8(e){if(e instanceof is||e instanceof ia||nK(),e instanceof is)return e;let t=e.getFilters();if(1===t.length)return a8(t[0]);if(ic(e))return e;let n=t.map(e=>a8(e)),r=[];return n.forEach(t=>{t instanceof is?r.push(t):t instanceof ia&&(t.op===e.op?r.push(...t.filters):r.push(t))}),1===r.length?r[0]:ia.create(r,e.op)}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class a7{constructor(){this.Je=new oe}addToCollectionParentIndex(e,t){return this.Je.add(t),ry.resolve()}getCollectionParents(e,t){return ry.resolve(this.Je.getEntries(t))}addFieldIndex(e,t){return ry.resolve()}deleteFieldIndex(e,t){return ry.resolve()}getDocumentsMatchingTarget(e,t){return ry.resolve(null)}getIndexType(e,t){return ry.resolve(0)}getFieldIndexes(e,t){return ry.resolve([])}getNextCollectionGroupToUpdate(e){return ry.resolve(null)}getMinOffset(e,t){return ry.resolve(rd.min())}getMinOffsetFromCollectionGroup(e,t){return ry.resolve(rd.min())}updateCollectionGroup(e,t,n){return ry.resolve()}updateIndexEntries(e,t){return ry.resolve()}}class oe{constructor(){this.index={}}add(e){let t=e.lastSegment(),n=e.popLast(),r=this.index[t]||new iS(rt.comparator),i=!r.has(n);return this.index[t]=r.add(n),i}has(e){let t=e.lastSegment(),n=e.popLast(),r=this.index[t];return r&&r.has(n)}getEntries(e){return(this.index[e]||new iS(rt.comparator)).toArray()}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ot=new Uint8Array(0);class on{constructor(e,t){this.user=e,this.databaseId=t,this.Ye=new oe,this.Xe=new sI(e=>iO(e),(e,t)=>iP(e,t)),this.uid=e.uid||""}addToCollectionParentIndex(e,t){if(!this.Ye.has(t)){let n=t.lastSegment(),r=t.popLast();e.addOnCommittedListener(()=>{this.Ye.add(t)});let i={collectionId:n,parent:an(r)};return or(e).put(i)}return ry.resolve()}getCollectionParents(e,t){let n=[],r=IDBKeyRange.bound([t,""],[t+"\x00",""],!1,!0);return or(e).W(r).next(e=>{for(let r of e){if(r.collectionId!==t)break;n.push(ar(r.parent))}return n})}addFieldIndex(e,t){let n=os(e),r={indexId:t.indexId,collectionGroup:t.collectionGroup,fields:t.fields.map(e=>[e.fieldPath.canonicalString(),e.kind])};delete r.indexId;let i=n.add(r);if(t.indexState){let n=oa(e);return i.next(e=>{n.put(aB(e,this.user,t.indexState.sequenceNumber,t.indexState.offset))})}return i.next()}deleteFieldIndex(e,t){let n=os(e),r=oa(e),i=oi(e);return n.delete(t.indexId).next(()=>r.delete(IDBKeyRange.bound([t.indexId],[t.indexId+1],!1,!0))).next(()=>i.delete(IDBKeyRange.bound([t.indexId],[t.indexId+1],!1,!0)))}getDocumentsMatchingTarget(e,t){let n=oi(e),r=!0,i=new Map;return ry.forEach(this.Ze(t),t=>this.tn(e,t).next(e=>{r&&(r=!!e),i.set(t,e)})).next(()=>{if(r){let e=sN(),r=[];return ry.forEach(i,(i,s)=>{nj("IndexedDbIndexManager",`Using index id=${i.indexId}|cg=${i.collectionGroup}|f=${i.fields.map(e=>`${e.fieldPath}:${e.kind}`).join(",")} to execute ${iO(t)}`);let a=function(e,t){let n=ra(t);if(void 0===n)return null;for(let t of iM(e,n.fieldPath))switch(t.op){case"array-contains-any":return t.value.arrayValue.values||[];case"array-contains":return[t.value]}return null}(s,i),o=function(e,t){let n=new Map;for(let r of ro(t))for(let t of iM(e,r.fieldPath))switch(t.op){case"==":case"in":n.set(r.fieldPath.canonicalString(),t.value);break;case"not-in":case"!=":return n.set(r.fieldPath.canonicalString(),t.value),Array.from(n.values())}return null}(s,i),l=function(e,t){let n=[],r=!0;for(let i of ro(t)){let t=0===i.kind?iU(e,i.fieldPath,e.startAt):iF(e,i.fieldPath,e.startAt);n.push(t.value),r&&(r=t.inclusive)}return new ie(n,r)}(s,i),u=function(e,t){let n=[],r=!0;for(let i of ro(t)){let t=0===i.kind?iF(e,i.fieldPath,e.endAt):iU(e,i.fieldPath,e.endAt);n.push(t.value),r&&(r=t.inclusive)}return new ie(n,r)}(s,i),c=this.en(i,s,l),h=this.en(i,s,u),d=this.nn(i,s,o),f=this.sn(i.indexId,a,c,l.inclusive,h,u.inclusive,d);return ry.forEach(f,i=>n.J(i,t.limit).next(t=>{t.forEach(t=>{let n=ri.fromSegments(t.documentKey);e.has(n)||(e=e.add(n),r.push(n))})}))}).next(()=>r)}return ry.resolve(null)})}Ze(e){let t=this.Xe.get(e);return t||(t=0===e.filters.length?[e]:(function(e){if(0===e.getFilters().length)return[];let t=function e(t){if(t instanceof is||t instanceof ia||nK(),t instanceof is)return t;if(1===t.filters.length)return e(t.filters[0]);let n=t.filters.map(t=>e(t)),r=ia.create(n,t.op);return a6(r=a8(r))?r:(r instanceof ia||nK(),io(r)||nK(),r.filters.length>1||nK(),r.filters.reduce((e,t)=>a5(e,t)))}(/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function e(t){var n,r;if(t instanceof is||t instanceof ia||nK(),t instanceof is){if(t instanceof iv){let e=(null===(r=null===(n=t.value.arrayValue)||void 0===n?void 0:n.values)||void 0===r?void 0:r.map(e=>is.create(t.field,"==",e)))||[];return ia.create(e,"or")}return t}let i=t.filters.map(t=>e(t));return ia.create(i,t.op)}(e));return a6(t)||nK(),a3(t)||a4(t)?[t]:t.getFilters()})(ia.create(e.filters,"and")).map(t=>iD(e.path,e.collectionGroup,e.orderBy,t.getFilters(),e.limit,e.startAt,e.endAt)),this.Xe.set(e,t)),t}sn(e,t,n,r,i,s,a){let o=(null!=t?t.length:1)*Math.max(n.length,i.length),l=o/(null!=t?t.length:1),u=[];for(let c=0;c<o;++c){let o=t?this.rn(t[c/l]):ot,h=this.on(e,o,n[c%l],r),d=this.un(e,o,i[c%l],s),f=a.map(t=>this.on(e,o,t,!0));u.push(...this.createRange(h,d,f))}return u}on(e,t,n,r){let i=new aZ(e,ri.empty(),t,n);return r?i:i.Ue()}un(e,t,n,r){let i=new aZ(e,ri.empty(),t,n);return r?i.Ue():i}tn(e,t){let n=new a2(t),r=null!=t.collectionGroup?t.collectionGroup:t.path.lastSegment();return this.getFieldIndexes(e,r).next(e=>{let t=null;for(let r of e)n.je(r)&&(!t||r.fields.length>t.fields.length)&&(t=r);return t})}getIndexType(e,t){let n=2,r=this.Ze(t);return ry.forEach(r,t=>this.tn(e,t).next(e=>{e?0!==n&&e.fields.length<function(e){let t=new iS(rr.comparator),n=!1;for(let r of e.filters)for(let e of r.getFlattenedFilters())e.field.isKeyField()||("array-contains"===e.op||"array-contains-any"===e.op?n=!0:t=t.add(e.field));for(let n of e.orderBy)n.field.isKeyField()||(t=t.add(n.field));return t.size+(n?1:0)}(t)&&(n=1):n=0})).next(()=>null!==t.limit&&r.length>1&&2===n?1:n)}cn(e,t){let n=new aJ;for(let r of ro(e)){let e=t.data.field(r.fieldPath);if(null==e)return null;let i=n.qe(r.kind);aW.Ie.ue(e,i)}return n.Fe()}rn(e){let t=new aJ;return aW.Ie.ue(e,t.qe(0)),t.Fe()}an(e,t){let n=new aJ;return aW.Ie.ue(r0(this.databaseId,t),n.qe(function(e){let t=ro(e);return 0===t.length?0:t[t.length-1].kind}(e))),n.Fe()}nn(e,t,n){if(null===n)return[];let r=[];r.push(new aJ);let i=0;for(let s of ro(e)){let e=n[i++];for(let n of r)if(this.hn(t,s.fieldPath)&&r2(e))r=this.ln(r,s,e);else{let t=n.qe(s.kind);aW.Ie.ue(e,t)}}return this.fn(r)}en(e,t,n){return this.nn(e,t,n.position)}fn(e){let t=[];for(let n=0;n<e.length;++n)t[n]=e[n].Fe();return t}ln(e,t,n){let r=[...e],i=[];for(let e of n.arrayValue.values||[])for(let n of r){let r=new aJ;r.seed(n.Fe()),aW.Ie.ue(e,r.qe(t.kind)),i.push(r)}return i}hn(e,t){return!!e.filters.find(e=>e instanceof is&&e.field.isEqual(t)&&("in"===e.op||"not-in"===e.op))}getFieldIndexes(e,t){let n=os(e),r=oa(e);return(t?n.W("collectionGroupIndex",IDBKeyRange.bound(t,t)):n.W()).next(e=>{let t=[];return ry.forEach(e,e=>r.get([e.indexId,this.uid]).next(n=>{t.push(function(e,t){let n=t?new ru(t.sequenceNumber,new rd(aP(t.readTime),new ri(ar(t.documentKey)),t.largestBatchId)):ru.empty(),r=e.fields.map(([e,t])=>new rl(rr.fromServerFormat(e),t));return new rs(e.indexId,e.collectionGroup,r,n)}(e,n))})).next(()=>t)})}getNextCollectionGroupToUpdate(e){return this.getFieldIndexes(e).next(e=>0===e.length?null:(e.sort((e,t)=>{let n=e.indexState.sequenceNumber-t.indexState.sequenceNumber;return 0!==n?n:n5(e.collectionGroup,t.collectionGroup)}),e[0].collectionGroup))}updateCollectionGroup(e,t,n){let r=os(e),i=oa(e);return this.dn(e).next(e=>r.W("collectionGroupIndex",IDBKeyRange.bound(t,t)).next(t=>ry.forEach(t,t=>i.put(aB(t.indexId,this.user,e,n)))))}updateIndexEntries(e,t){let n=new Map;return ry.forEach(t,(t,r)=>{let i=n.get(t.collectionGroup);return(i?ry.resolve(i):this.getFieldIndexes(e,t.collectionGroup)).next(i=>(n.set(t.collectionGroup,i),ry.forEach(i,n=>this._n(e,t,n).next(t=>{let i=this.wn(r,n);return t.isEqual(i)?ry.resolve():this.mn(e,r,n,t,i)}))))})}gn(e,t,n,r){return oi(e).put({indexId:r.indexId,uid:this.uid,arrayValue:r.arrayValue,directionalValue:r.directionalValue,orderedDocumentKey:this.an(n,t.key),documentKey:t.key.path.toArray()})}yn(e,t,n,r){return oi(e).delete([r.indexId,this.uid,r.arrayValue,r.directionalValue,this.an(n,t.key),t.key.path.toArray()])}_n(e,t,n){let r=oi(e),i=new iS(a0);return r.Z({index:"documentKeyIndex",range:IDBKeyRange.only([n.indexId,this.uid,this.an(n,t)])},(e,r)=>{i=i.add(new aZ(n.indexId,t,r.arrayValue,r.directionalValue))}).next(()=>i)}wn(e,t){let n=new iS(a0),r=this.cn(t,e);if(null==r)return n;let i=ra(t);if(null!=i){let s=e.data.field(i.fieldPath);if(r2(s))for(let i of s.arrayValue.values||[])n=n.add(new aZ(t.indexId,e.key,this.rn(i),r))}else n=n.add(new aZ(t.indexId,e.key,ot,r));return n}mn(e,t,n,r,i){nj("IndexedDbIndexManager","Updating index entries for document '%s'",t.key);let s=[];return function(e,t,n,r,i){let s=e.getIterator(),a=t.getIterator(),o=iA(s),l=iA(a);for(;o||l;){let e=!1,t=!1;if(o&&l){let r=n(o,l);r<0?t=!0:r>0&&(e=!0)}else null!=o?t=!0:e=!0;e?(r(l),l=iA(a)):t?(i(o),o=iA(s)):(o=iA(s),l=iA(a))}}(r,i,a0,r=>{s.push(this.gn(e,t,n,r))},r=>{s.push(this.yn(e,t,n,r))}),ry.waitFor(s)}dn(e){let t=1;return oa(e).Z({index:"sequenceNumberIndex",reverse:!0,range:IDBKeyRange.upperBound([this.uid,Number.MAX_SAFE_INTEGER])},(e,n,r)=>{r.done(),t=n.sequenceNumber+1}).next(()=>t)}createRange(e,t,n){n=n.sort((e,t)=>a0(e,t)).filter((e,t,n)=>!t||0!==a0(e,n[t-1]));let r=[];for(let i of(r.push(e),n)){let n=a0(i,e),s=a0(i,t);if(0===n)r[0]=e.Ue();else if(n>0&&s<0)r.push(i),r.push(i.Ue());else if(s>0)break}r.push(t);let i=[];for(let e=0;e<r.length;e+=2){if(this.pn(r[e],r[e+1]))return[];let t=[r[e].indexId,this.uid,r[e].arrayValue,r[e].directionalValue,ot,[]],n=[r[e+1].indexId,this.uid,r[e+1].arrayValue,r[e+1].directionalValue,ot,[]];i.push(IDBKeyRange.bound(t,n))}return i}pn(e,t){return a0(e,t)>0}getMinOffsetFromCollectionGroup(e,t){return this.getFieldIndexes(e,t).next(oo)}getMinOffset(e,t){return ry.mapArray(this.Ze(t),t=>this.tn(e,t).next(e=>e||nK())).next(oo)}}function or(e){return aS(e,"collectionParents")}function oi(e){return aS(e,"indexEntries")}function os(e){return aS(e,"indexConfiguration")}function oa(e){return aS(e,"indexState")}function oo(e){0!==e.length||nK();let t=e[0].indexState.offset,n=t.largestBatchId;for(let r=1;r<e.length;r++){let i=e[r].indexState.offset;0>rf(i,t)&&(t=i),n<i.largestBatchId&&(n=i.largestBatchId)}return new rd(t.readTime,t.documentKey,n)}/**
 * @license
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ol={didRun:!1,sequenceNumbersCollected:0,targetsRemoved:0,documentsRemoved:0};class ou{constructor(e,t,n){this.cacheSizeCollectionThreshold=e,this.percentileToCollect=t,this.maximumSequenceNumbersToCollect=n}static withCacheSize(e){return new ou(e,ou.DEFAULT_COLLECTION_PERCENTILE,ou.DEFAULT_MAX_SEQUENCE_NUMBERS_TO_COLLECT)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function oc(e,t,n){let r=e.store("mutations"),i=e.store("documentMutations"),s=[],a=IDBKeyRange.only(n.batchId),o=0,l=r.Z({range:a},(e,t,n)=>(o++,n.delete()));s.push(l.next(()=>{1===o||nK()}));let u=[];for(let e of n.mutations){var c,h;let r=(c=e.key.path,h=n.batchId,[t,an(c),h]);s.push(i.delete(r)),u.push(e.key)}return ry.waitFor(s).next(()=>u)}function oh(e){let t;if(!e)return 0;if(e.document)t=e.document;else if(e.unknownDocument)t=e.unknownDocument;else{if(!e.noDocument)throw nK();t=e.noDocument}return JSON.stringify(t).length}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ou.DEFAULT_COLLECTION_PERCENTILE=10,ou.DEFAULT_MAX_SEQUENCE_NUMBERS_TO_COLLECT=1e3,ou.DEFAULT=new ou(41943040,ou.DEFAULT_COLLECTION_PERCENTILE,ou.DEFAULT_MAX_SEQUENCE_NUMBERS_TO_COLLECT),ou.DISABLED=new ou(-1,0,0);class od{constructor(e,t,n,r){this.userId=e,this.yt=t,this.indexManager=n,this.referenceDelegate=r,this.In={}}static re(e,t,n,r){""!==e.uid||nK();let i=e.isAuthenticated()?e.uid:"";return new od(i,t,n,r)}checkEmpty(e){let t=!0,n=IDBKeyRange.bound([this.userId,Number.NEGATIVE_INFINITY],[this.userId,Number.POSITIVE_INFINITY]);return op(e).Z({index:"userMutationsIndex",range:n},(e,n,r)=>{t=!1,r.done()}).next(()=>t)}addMutationBatch(e,t,n,r){let i=om(e),s=op(e);return s.add({}).next(a=>{"number"==typeof a||nK();let o=new ak(a,t,n,r),l=function(e,t,n){let r=n.baseMutations.map(t=>s4(e.ie,t)),i=n.mutations.map(t=>s4(e.ie,t));return{userId:t,batchId:n.batchId,localWriteTimeMs:n.localWriteTime.toMillis(),baseMutations:r,mutations:i}}(this.yt,this.userId,o),u=[],c=new iS((e,t)=>n5(e.canonicalString(),t.canonicalString()));for(let e of r){let t=[this.userId,an(e.key.path),a];c=c.add(e.key.path.popLast()),u.push(s.put(l)),u.push(i.put(t,as))}return c.forEach(t=>{u.push(this.indexManager.addToCollectionParentIndex(e,t))}),e.addOnCommittedListener(()=>{this.In[a]=o.keys()}),ry.waitFor(u).next(()=>o)})}lookupMutationBatch(e,t){return op(e).get(t).next(e=>e?(e.userId===this.userId||nK(),aL(this.yt,e)):null)}Tn(e,t){return this.In[t]?ry.resolve(this.In[t]):this.lookupMutationBatch(e,t).next(e=>{if(e){let n=e.keys();return this.In[t]=n,n}return null})}getNextMutationBatchAfterBatchId(e,t){let n=t+1,r=IDBKeyRange.lowerBound([this.userId,n]),i=null;return op(e).Z({index:"userMutationsIndex",range:r},(e,t,r)=>{t.userId===this.userId&&(t.batchId>=n||nK(),i=aL(this.yt,t)),r.done()}).next(()=>i)}getHighestUnacknowledgedBatchId(e){let t=IDBKeyRange.upperBound([this.userId,Number.POSITIVE_INFINITY]),n=-1;return op(e).Z({index:"userMutationsIndex",range:t,reverse:!0},(e,t,r)=>{n=t.batchId,r.done()}).next(()=>n)}getAllMutationBatches(e){let t=IDBKeyRange.bound([this.userId,-1],[this.userId,Number.POSITIVE_INFINITY]);return op(e).W("userMutationsIndex",t).next(e=>e.map(e=>aL(this.yt,e)))}getAllMutationBatchesAffectingDocumentKey(e,t){let n=[this.userId,an(t.path)],r=IDBKeyRange.lowerBound(n),i=[];return om(e).Z({range:r},(n,r,s)=>{let[a,o,l]=n,u=ar(o);if(a===this.userId&&t.path.isEqual(u))return op(e).get(l).next(e=>{if(!e)throw nK();e.userId===this.userId||nK(),i.push(aL(this.yt,e))});s.done()}).next(()=>i)}getAllMutationBatchesAffectingDocumentKeys(e,t){let n=new iS(n5),r=[];return t.forEach(t=>{let i=[this.userId,an(t.path)],s=IDBKeyRange.lowerBound(i),a=om(e).Z({range:s},(e,r,i)=>{let[s,a,o]=e,l=ar(a);s===this.userId&&t.path.isEqual(l)?n=n.add(o):i.done()});r.push(a)}),ry.waitFor(r).next(()=>this.En(e,n))}getAllMutationBatchesAffectingQuery(e,t){let n=t.path,r=n.length+1,i=[this.userId,an(n)],s=IDBKeyRange.lowerBound(i),a=new iS(n5);return om(e).Z({range:s},(e,t,i)=>{let[s,o,l]=e,u=ar(o);s===this.userId&&n.isPrefixOf(u)?u.length===r&&(a=a.add(l)):i.done()}).next(()=>this.En(e,a))}En(e,t){let n=[],r=[];return t.forEach(t=>{r.push(op(e).get(t).next(e=>{if(null===e)throw nK();e.userId===this.userId||nK(),n.push(aL(this.yt,e))}))}),ry.waitFor(r).next(()=>n)}removeMutationBatch(e,t){return oc(e.se,this.userId,t).next(n=>(e.addOnCommittedListener(()=>{this.An(t.batchId)}),ry.forEach(n,t=>this.referenceDelegate.markPotentiallyOrphaned(e,t))))}An(e){delete this.In[e]}performConsistencyCheck(e){return this.checkEmpty(e).next(t=>{if(!t)return ry.resolve();let n=IDBKeyRange.lowerBound([this.userId]),r=[];return om(e).Z({range:n},(e,t,n)=>{if(e[0]===this.userId){let t=ar(e[1]);r.push(t)}else n.done()}).next(()=>{0===r.length||nK()})})}containsKey(e,t){return of(e,this.userId,t)}Rn(e){return og(e).get(this.userId).next(e=>e||{userId:this.userId,lastAcknowledgedBatchId:-1,lastStreamToken:""})}}function of(e,t,n){let r=[t,an(n.path)],i=r[1],s=IDBKeyRange.lowerBound(r),a=!1;return om(e).Z({range:s,X:!0},(e,n,r)=>{let[s,o,l]=e;s===t&&o===i&&(a=!0),r.done()}).next(()=>a)}function op(e){return aS(e,"mutations")}function om(e){return aS(e,"documentMutations")}function og(e){return aS(e,"mutationQueues")}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oy{constructor(e){this.bn=e}next(){return this.bn+=2,this.bn}static Pn(){return new oy(0)}static vn(){return new oy(-1)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ov{constructor(e,t){this.referenceDelegate=e,this.yt=t}allocateTargetId(e){return this.Vn(e).next(t=>{let n=new oy(t.highestTargetId);return t.highestTargetId=n.next(),this.Sn(e,t).next(()=>t.highestTargetId)})}getLastRemoteSnapshotVersion(e){return this.Vn(e).next(e=>n7.fromTimestamp(new n8(e.lastRemoteSnapshotVersion.seconds,e.lastRemoteSnapshotVersion.nanoseconds)))}getHighestSequenceNumber(e){return this.Vn(e).next(e=>e.highestListenSequenceNumber)}setTargetsMetadata(e,t,n){return this.Vn(e).next(r=>(r.highestListenSequenceNumber=t,n&&(r.lastRemoteSnapshotVersion=n.toTimestamp()),t>r.highestListenSequenceNumber&&(r.highestListenSequenceNumber=t),this.Sn(e,r)))}addTargetData(e,t){return this.Dn(e,t).next(()=>this.Vn(e).next(n=>(n.targetCount+=1,this.Cn(t,n),this.Sn(e,n))))}updateTargetData(e,t){return this.Dn(e,t)}removeTargetData(e,t){return this.removeMatchingKeysForTargetId(e,t.targetId).next(()=>ow(e).delete(t.targetId)).next(()=>this.Vn(e)).next(t=>(t.targetCount>0||nK(),t.targetCount-=1,this.Sn(e,t)))}removeTargets(e,t,n){let r=0,i=[];return ow(e).Z((s,a)=>{let o=aM(a);o.sequenceNumber<=t&&null===n.get(o.targetId)&&(r++,i.push(this.removeTargetData(e,o)))}).next(()=>ry.waitFor(i)).next(()=>r)}forEachTarget(e,t){return ow(e).Z((e,n)=>{let r=aM(n);t(r)})}Vn(e){return o_(e).get("targetGlobalKey").next(e=>(null!==e||nK(),e))}Sn(e,t){return o_(e).put("targetGlobalKey",t)}Dn(e,t){return ow(e).put(aU(this.yt,t))}Cn(e,t){let n=!1;return e.targetId>t.highestTargetId&&(t.highestTargetId=e.targetId,n=!0),e.sequenceNumber>t.highestListenSequenceNumber&&(t.highestListenSequenceNumber=e.sequenceNumber,n=!0),n}getTargetCount(e){return this.Vn(e).next(e=>e.targetCount)}getTargetData(e,t){let n=iO(t),r=IDBKeyRange.bound([n,Number.NEGATIVE_INFINITY],[n,Number.POSITIVE_INFINITY]),i=null;return ow(e).Z({range:r,index:"queryTargetsIndex"},(e,n,r)=>{let s=aM(n);iP(t,s.target)&&(i=s,r.done())}).next(()=>i)}addMatchingKeys(e,t,n){let r=[],i=ob(e);return t.forEach(t=>{let s=an(t.path);r.push(i.put({targetId:n,path:s})),r.push(this.referenceDelegate.addReference(e,n,t))}),ry.waitFor(r)}removeMatchingKeys(e,t,n){let r=ob(e);return ry.forEach(t,t=>{let i=an(t.path);return ry.waitFor([r.delete([n,i]),this.referenceDelegate.removeReference(e,n,t)])})}removeMatchingKeysForTargetId(e,t){let n=ob(e),r=IDBKeyRange.bound([t],[t+1],!1,!0);return n.delete(r)}getMatchingKeysForTargetId(e,t){let n=IDBKeyRange.bound([t],[t+1],!1,!0),r=ob(e),i=sN();return r.Z({range:n,X:!0},(e,t,n)=>{let r=ar(e[1]),s=new ri(r);i=i.add(s)}).next(()=>i)}containsKey(e,t){let n=an(t.path),r=IDBKeyRange.bound([n],[n+"\x00"],!1,!0),i=0;return ob(e).Z({index:"documentTargetsIndex",X:!0,range:r},([e,t],n,r)=>{0!==e&&(i++,r.done())}).next(()=>i>0)}ne(e,t){return ow(e).get(t).next(e=>e?aM(e):null)}}function ow(e){return aS(e,"targets")}function o_(e){return aS(e,"targetGlobal")}function ob(e){return aS(e,"targetDocuments")}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function oI([e,t],[n,r]){let i=n5(e,n);return 0===i?n5(t,r):i}class oT{constructor(e){this.xn=e,this.buffer=new iS(oI),this.Nn=0}kn(){return++this.Nn}On(e){let t=[e,this.kn()];if(this.buffer.size<this.xn)this.buffer=this.buffer.add(t);else{let e=this.buffer.last();0>oI(t,e)&&(this.buffer=this.buffer.delete(e).add(t))}}get maxValue(){return this.buffer.last()[0]}}class oE{constructor(e,t,n){this.garbageCollector=e,this.asyncQueue=t,this.localStore=n,this.Mn=null}start(){-1!==this.garbageCollector.params.cacheSizeCollectionThreshold&&this.Fn(6e4)}stop(){this.Mn&&(this.Mn.cancel(),this.Mn=null)}get started(){return null!==this.Mn}Fn(e){nj("LruGarbageCollector",`Garbage collection scheduled in ${e}ms`),this.Mn=this.asyncQueue.enqueueAfterDelay("lru_garbage_collection",e,async()=>{this.Mn=null;try{await this.localStore.collectGarbage(this.garbageCollector)}catch(e){rI(e)?nj("LruGarbageCollector","Ignoring IndexedDB error during garbage collection: ",e):await rg(e)}await this.Fn(3e5)})}}class oS{constructor(e,t){this.$n=e,this.params=t}calculateTargetCount(e,t){return this.$n.Bn(e).next(e=>Math.floor(t/100*e))}nthSequenceNumber(e,t){if(0===t)return ry.resolve(rx.at);let n=new oT(t);return this.$n.forEachTarget(e,e=>n.On(e.sequenceNumber)).next(()=>this.$n.Ln(e,e=>n.On(e))).next(()=>n.maxValue)}removeTargets(e,t,n){return this.$n.removeTargets(e,t,n)}removeOrphanedDocuments(e,t){return this.$n.removeOrphanedDocuments(e,t)}collect(e,t){return -1===this.params.cacheSizeCollectionThreshold?(nj("LruGarbageCollector","Garbage collection skipped; disabled"),ry.resolve(ol)):this.getCacheSize(e).next(n=>n<this.params.cacheSizeCollectionThreshold?(nj("LruGarbageCollector",`Garbage collection skipped; Cache size ${n} is lower than threshold ${this.params.cacheSizeCollectionThreshold}`),ol):this.qn(e,t))}getCacheSize(e){return this.$n.getCacheSize(e)}qn(e,t){let n,r,i,s,a,o,l;let u=Date.now();return this.calculateTargetCount(e,this.params.percentileToCollect).next(t=>(t>this.params.maximumSequenceNumbersToCollect?(nj("LruGarbageCollector",`Capping sequence numbers to collect down to the maximum of ${this.params.maximumSequenceNumbersToCollect} from ${t}`),r=this.params.maximumSequenceNumbersToCollect):r=t,s=Date.now(),this.nthSequenceNumber(e,r))).next(r=>(n=r,a=Date.now(),this.removeTargets(e,n,t))).next(t=>(i=t,o=Date.now(),this.removeOrphanedDocuments(e,n))).next(e=>(l=Date.now(),nq()<=f.in.DEBUG&&nj("LruGarbageCollector",`LRU Garbage Collection
	Counted targets in ${s-u}ms
	Determined least recently used ${r} in `+(a-s)+"ms\n"+`	Removed ${i} targets in `+(o-a)+"ms\n"+`	Removed ${e} documents in `+(l-o)+"ms\n"+`Total Duration: ${l-u}ms`),ry.resolve({didRun:!0,sequenceNumbersCollected:r,targetsRemoved:i,documentsRemoved:e})))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ok{constructor(e,t){this.db=e,this.garbageCollector=new oS(this,t)}Bn(e){let t=this.Un(e);return this.db.getTargetCache().getTargetCount(e).next(e=>t.next(t=>e+t))}Un(e){let t=0;return this.Ln(e,e=>{t++}).next(()=>t)}forEachTarget(e,t){return this.db.getTargetCache().forEachTarget(e,t)}Ln(e,t){return this.Kn(e,(e,n)=>t(n))}addReference(e,t,n){return oA(e,n)}removeReference(e,t,n){return oA(e,n)}removeTargets(e,t,n){return this.db.getTargetCache().removeTargets(e,t,n)}markPotentiallyOrphaned(e,t){return oA(e,t)}Gn(e,t){let n;return n=!1,og(e).tt(r=>of(e,r,t).next(e=>(e&&(n=!0),ry.resolve(!e)))).next(()=>n)}removeOrphanedDocuments(e,t){let n=this.db.getRemoteDocumentCache().newChangeBuffer(),r=[],i=0;return this.Kn(e,(s,a)=>{if(a<=t){let t=this.Gn(e,s).next(t=>{if(!t)return i++,n.getEntry(e,s).next(()=>(n.removeEntry(s,n7.min()),ob(e).delete([0,an(s.path)])))});r.push(t)}}).next(()=>ry.waitFor(r)).next(()=>n.apply(e)).next(()=>i)}removeTarget(e,t){let n=t.withSequenceNumber(e.currentSequenceNumber);return this.db.getTargetCache().updateTargetData(e,n)}updateLimboDocument(e,t){return oA(e,t)}Kn(e,t){let n=ob(e),r,i=rx.at;return n.Z({index:"documentTargetsIndex"},([e,n],{path:s,sequenceNumber:a})=>{0===e?(i!==rx.at&&t(new ri(ar(r)),i),i=a,r=s):i=rx.at}).next(()=>{i!==rx.at&&t(new ri(ar(r)),i)})}getCacheSize(e){return this.db.getRemoteDocumentCache().getSize(e)}}function oA(e,t){var n;return ob(e).put((n=e.currentSequenceNumber,{targetId:0,path:an(t.path),sequenceNumber:n}))}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oC{constructor(){this.changes=new sI(e=>e.toString(),(e,t)=>e.isEqual(t)),this.changesApplied=!1}addEntry(e){this.assertNotApplied(),this.changes.set(e.key,e)}removeEntry(e,t){this.assertNotApplied(),this.changes.set(e,iN.newInvalidDocument(e).setReadTime(t))}getEntry(e,t){this.assertNotApplied();let n=this.changes.get(t);return void 0!==n?ry.resolve(n):this.getFromCache(e,t)}getEntries(e,t){return this.getAllFromCache(e,t)}apply(e){return this.assertNotApplied(),this.changesApplied=!0,this.applyChanges(e)}assertNotApplied(){}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ox{constructor(e){this.yt=e}setIndexManager(e){this.indexManager=e}addEntry(e,t,n){return oD(e).put(n)}removeEntry(e,t,n){return oD(e).delete(function(e,t){let n=e.path.toArray();return[n.slice(0,n.length-2),n[n.length-2],aD(t),n[n.length-1]]}(t,n))}updateMetadata(e,t){return this.getMetadata(e).next(n=>(n.byteSize+=t,this.Qn(e,n)))}getEntry(e,t){let n=iN.newInvalidDocument(t);return oD(e).Z({index:"documentKeyIndex",range:IDBKeyRange.only(oO(t))},(e,r)=>{n=this.jn(t,r)}).next(()=>n)}Wn(e,t){let n={size:0,document:iN.newInvalidDocument(t)};return oD(e).Z({index:"documentKeyIndex",range:IDBKeyRange.only(oO(t))},(e,r)=>{n={document:this.jn(t,r),size:oh(r)}}).next(()=>n)}getEntries(e,t){let n=sT;return this.zn(e,t,(e,t)=>{let r=this.jn(e,t);n=n.insert(e,r)}).next(()=>n)}Hn(e,t){let n=sT,r=new iI(ri.comparator);return this.zn(e,t,(e,t)=>{let i=this.jn(e,t);n=n.insert(e,i),r=r.insert(e,oh(t))}).next(()=>({documents:n,Jn:r}))}zn(e,t,n){if(t.isEmpty())return ry.resolve();let r=new iS(oL);t.forEach(e=>r=r.add(e));let i=IDBKeyRange.bound(oO(r.first()),oO(r.last())),s=r.getIterator(),a=s.getNext();return oD(e).Z({index:"documentKeyIndex",range:i},(e,t,r)=>{let i=ri.fromSegments([...t.prefixPath,t.collectionGroup,t.documentId]);for(;a&&0>oL(a,i);)n(a,null),a=s.getNext();a&&a.isEqual(i)&&(n(a,t),a=s.hasNext()?s.getNext():null),a?r.j(oO(a)):r.done()}).next(()=>{for(;a;)n(a,null),a=s.hasNext()?s.getNext():null})}getDocumentsMatchingQuery(e,t,n,r){let i=t.path,s=[i.popLast().toArray(),i.lastSegment(),aD(n.readTime),n.documentKey.path.isEmpty()?"":n.documentKey.path.lastSegment()],a=[i.popLast().toArray(),i.lastSegment(),[Number.MAX_SAFE_INTEGER,Number.MAX_SAFE_INTEGER],""];return oD(e).W(IDBKeyRange.bound(s,a,!0)).next(e=>{let n=sT;for(let i of e){let e=this.jn(ri.fromSegments(i.prefixPath.concat(i.collectionGroup,i.documentId)),i);e.isFoundDocument()&&(iJ(t,e)||r.has(e.key))&&(n=n.insert(e.key,e))}return n})}getAllFromCollectionGroup(e,t,n,r){let i=sT,s=oP(t,n),a=oP(t,rd.max());return oD(e).Z({index:"collectionGroupIndex",range:IDBKeyRange.bound(s,a,!0)},(e,t,n)=>{let s=this.jn(ri.fromSegments(t.prefixPath.concat(t.collectionGroup,t.documentId)),t);(i=i.insert(s.key,s)).size===r&&n.done()}).next(()=>i)}newChangeBuffer(e){return new oN(this,!!e&&e.trackRemovals)}getSize(e){return this.getMetadata(e).next(e=>e.byteSize)}getMetadata(e){return oR(e).get("remoteDocumentGlobalKey").next(e=>(e||nK(),e))}Qn(e,t){return oR(e).put("remoteDocumentGlobalKey",t)}jn(e,t){if(t){let e=function(e,t){let n;if(t.document)n=s3(e.ie,t.document,!!t.hasCommittedMutations);else if(t.noDocument){let e=ri.fromSegments(t.noDocument.path),r=aP(t.noDocument.readTime);n=iN.newNoDocument(e,r),t.hasCommittedMutations&&n.setHasCommittedMutations()}else{if(!t.unknownDocument)return nK();{let e=ri.fromSegments(t.unknownDocument.path),r=aP(t.unknownDocument.version);n=iN.newUnknownDocument(e,r)}}return t.readTime&&n.setReadTime(function(e){let t=new n8(e[0],e[1]);return n7.fromTimestamp(t)}(t.readTime)),n}(this.yt,t);if(!(e.isNoDocument()&&e.version.isEqual(n7.min())))return e}return iN.newInvalidDocument(e)}}class oN extends oC{constructor(e,t){super(),this.Yn=e,this.trackRemovals=t,this.Xn=new sI(e=>e.toString(),(e,t)=>e.isEqual(t))}applyChanges(e){let t=[],n=0,r=new iS((e,t)=>n5(e.canonicalString(),t.canonicalString()));return this.changes.forEach((i,s)=>{let a=this.Xn.get(i);if(t.push(this.Yn.removeEntry(e,i,a.readTime)),s.isValidDocument()){let o=aR(this.Yn.yt,s);r=r.add(i.path.popLast());let l=oh(o);n+=l-a.size,t.push(this.Yn.addEntry(e,i,o))}else if(n-=a.size,this.trackRemovals){let n=aR(this.Yn.yt,s.convertToNoDocument(n7.min()));t.push(this.Yn.addEntry(e,i,n))}}),r.forEach(n=>{t.push(this.Yn.indexManager.addToCollectionParentIndex(e,n))}),t.push(this.Yn.updateMetadata(e,n)),ry.waitFor(t)}getFromCache(e,t){return this.Yn.Wn(e,t).next(e=>(this.Xn.set(t,{size:e.size,readTime:e.document.readTime}),e.document))}getAllFromCache(e,t){return this.Yn.Hn(e,t).next(({documents:e,Jn:t})=>(t.forEach((t,n)=>{this.Xn.set(t,{size:n,readTime:e.get(t).readTime})}),e))}}function oR(e){return aS(e,"remoteDocumentGlobal")}function oD(e){return aS(e,"remoteDocumentsV14")}function oO(e){let t=e.path.toArray();return[t.slice(0,t.length-2),t[t.length-2],t[t.length-1]]}function oP(e,t){let n=t.documentKey.path.toArray();return[e,aD(t.readTime),n.slice(0,n.length-2),n.length>0?n[n.length-1]:""]}function oL(e,t){let n=e.path.toArray(),r=t.path.toArray(),i=0;for(let e=0;e<n.length-2&&e<r.length-2;++e)if(i=n5(n[e],r[e]))return i;return(i=n5(n.length,r.length))||(i=n5(n[n.length-2],r[r.length-2]))||n5(n[n.length-1],r[r.length-1])}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oM{constructor(e,t){this.overlayedDocument=e,this.mutatedFields=t}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oU{constructor(e,t,n,r){this.remoteDocumentCache=e,this.mutationQueue=t,this.documentOverlayCache=n,this.indexManager=r}getDocument(e,t){let n=null;return this.documentOverlayCache.getOverlay(e,t).next(r=>(n=r,this.remoteDocumentCache.getEntry(e,t))).next(e=>(null!==n&&sc(n.mutation,e,iC.empty(),n8.now()),e))}getDocuments(e,t){return this.remoteDocumentCache.getEntries(e,t).next(t=>this.getLocalViewOfDocuments(e,t,sN()).next(()=>t))}getLocalViewOfDocuments(e,t,n=sN()){let r=sA();return this.populateOverlays(e,r,t).next(()=>this.computeViews(e,t,r,n).next(e=>{let t=sS();return e.forEach((e,n)=>{t=t.insert(e,n.overlayedDocument)}),t}))}getOverlayedDocuments(e,t){let n=sA();return this.populateOverlays(e,n,t).next(()=>this.computeViews(e,t,n,sN()))}populateOverlays(e,t,n){let r=[];return n.forEach(e=>{t.has(e)||r.push(e)}),this.documentOverlayCache.getOverlays(e,r).next(e=>{e.forEach((e,n)=>{t.set(e,n)})})}computeViews(e,t,n,r){let i=sT,s=sA(),a=sA();return t.forEach((e,t)=>{let a=n.get(t.key);r.has(t.key)&&(void 0===a||a.mutation instanceof sf)?i=i.insert(t.key,t):void 0!==a?(s.set(t.key,a.mutation.getFieldMask()),sc(a.mutation,t,a.mutation.getFieldMask(),n8.now())):s.set(t.key,iC.empty())}),this.recalculateAndSaveOverlays(e,i).next(e=>(e.forEach((e,t)=>s.set(e,t)),t.forEach((e,t)=>{var n;return a.set(e,new oM(t,null!==(n=s.get(e))&&void 0!==n?n:null))}),a))}recalculateAndSaveOverlays(e,t){let n=sA(),r=new iI((e,t)=>e-t),i=sN();return this.mutationQueue.getAllMutationBatchesAffectingDocumentKeys(e,t).next(e=>{for(let i of e)i.keys().forEach(e=>{let s=t.get(e);if(null===s)return;let a=n.get(e)||iC.empty();a=i.applyToLocalView(s,a),n.set(e,a);let o=(r.get(i.batchId)||sN()).add(e);r=r.insert(i.batchId,o)})}).next(()=>{let s=[],a=r.getReverseIterator();for(;a.hasNext();){let r=a.getNext(),o=r.key,l=r.value,u=sA();l.forEach(e=>{if(!i.has(e)){let r=su(t.get(e),n.get(e));null!==r&&u.set(e,r),i=i.add(e)}}),s.push(this.documentOverlayCache.saveOverlays(e,o,u))}return ry.waitFor(s)}).next(()=>n)}recalculateAndSaveOverlaysForDocumentKeys(e,t){return this.remoteDocumentCache.getEntries(e,t).next(t=>this.recalculateAndSaveOverlays(e,t))}getDocumentsMatchingQuery(e,t,n){return ri.isDocumentKey(t.path)&&null===t.collectionGroup&&0===t.filters.length?this.getDocumentsMatchingDocumentQuery(e,t.path):i$(t)?this.getDocumentsMatchingCollectionGroupQuery(e,t,n):this.getDocumentsMatchingCollectionQuery(e,t,n)}getNextDocuments(e,t,n,r){return this.remoteDocumentCache.getAllFromCollectionGroup(e,t,n,r).next(i=>{let s=r-i.size>0?this.documentOverlayCache.getOverlaysForCollectionGroup(e,t,n.largestBatchId,r-i.size):ry.resolve(sA()),a=-1,o=i;return s.next(t=>ry.forEach(t,(t,n)=>(a<n.largestBatchId&&(a=n.largestBatchId),i.get(t)?ry.resolve():this.remoteDocumentCache.getEntry(e,t).next(e=>{o=o.insert(t,e)}))).next(()=>this.populateOverlays(e,t,i)).next(()=>this.computeViews(e,o,t,sN())).next(e=>({batchId:a,changes:sk(e)})))})}getDocumentsMatchingDocumentQuery(e,t){return this.getDocument(e,new ri(t)).next(e=>{let t=sS();return e.isFoundDocument()&&(t=t.insert(e.key,e)),t})}getDocumentsMatchingCollectionGroupQuery(e,t,n){let r=t.collectionGroup,i=sS();return this.indexManager.getCollectionParents(e,r).next(s=>ry.forEach(s,s=>{var a;let o=(a=s.child(r),new iV(a,null,t.explicitOrderBy.slice(),t.filters.slice(),t.limit,t.limitType,t.startAt,t.endAt));return this.getDocumentsMatchingCollectionQuery(e,o,n).next(e=>{e.forEach((e,t)=>{i=i.insert(e,t)})})}).next(()=>i))}getDocumentsMatchingCollectionQuery(e,t,n){let r;return this.documentOverlayCache.getOverlaysForCollection(e,t.path,n.largestBatchId).next(i=>(r=i,this.remoteDocumentCache.getDocumentsMatchingQuery(e,t,n,r))).next(e=>{r.forEach((t,n)=>{let r=n.getKey();null===e.get(r)&&(e=e.insert(r,iN.newInvalidDocument(r)))});let n=sS();return e.forEach((e,i)=>{let s=r.get(e);void 0!==s&&sc(s.mutation,i,iC.empty(),n8.now()),iJ(t,i)&&(n=n.insert(e,i))}),n})}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oF{constructor(e){this.yt=e,this.Zn=new Map,this.ts=new Map}getBundleMetadata(e,t){return ry.resolve(this.Zn.get(t))}saveBundleMetadata(e,t){return this.Zn.set(t.id,{id:t.id,version:t.version,createTime:sW(t.createTime)}),ry.resolve()}getNamedQuery(e,t){return ry.resolve(this.ts.get(t))}saveNamedQuery(e,t){return this.ts.set(t.name,{name:t.name,query:aF(t.bundledQuery),readTime:sW(t.readTime)}),ry.resolve()}}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oV{constructor(){this.overlays=new iI(ri.comparator),this.es=new Map}getOverlay(e,t){return ry.resolve(this.overlays.get(t))}getOverlays(e,t){let n=sA();return ry.forEach(t,t=>this.getOverlay(e,t).next(e=>{null!==e&&n.set(t,e)})).next(()=>n)}saveOverlays(e,t,n){return n.forEach((n,r)=>{this.oe(e,t,r)}),ry.resolve()}removeOverlaysForBatchId(e,t,n){let r=this.es.get(n);return void 0!==r&&(r.forEach(e=>this.overlays=this.overlays.remove(e)),this.es.delete(n)),ry.resolve()}getOverlaysForCollection(e,t,n){let r=sA(),i=t.length+1,s=new ri(t.child("")),a=this.overlays.getIteratorFrom(s);for(;a.hasNext();){let e=a.getNext().value,s=e.getKey();if(!t.isPrefixOf(s.path))break;s.path.length===i&&e.largestBatchId>n&&r.set(e.getKey(),e)}return ry.resolve(r)}getOverlaysForCollectionGroup(e,t,n,r){let i=new iI((e,t)=>e-t),s=this.overlays.getIterator();for(;s.hasNext();){let e=s.getNext().value;if(e.getKey().getCollectionGroup()===t&&e.largestBatchId>n){let t=i.get(e.largestBatchId);null===t&&(t=sA(),i=i.insert(e.largestBatchId,t)),t.set(e.getKey(),e)}}let a=sA(),o=i.getIterator();for(;o.hasNext()&&(o.getNext().value.forEach((e,t)=>a.set(e,t)),!(a.size()>=r)););return ry.resolve(a)}oe(e,t,n){let r=this.overlays.get(n.key);if(null!==r){let e=this.es.get(r.largestBatchId).delete(n.key);this.es.set(r.largestBatchId,e)}this.overlays=this.overlays.insert(n.key,new aC(t,n));let i=this.es.get(t);void 0===i&&(i=sN(),this.es.set(t,i)),this.es.set(t,i.add(n.key))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oq{constructor(){this.ns=new iS(oB.ss),this.rs=new iS(oB.os)}isEmpty(){return this.ns.isEmpty()}addReference(e,t){let n=new oB(e,t);this.ns=this.ns.add(n),this.rs=this.rs.add(n)}us(e,t){e.forEach(e=>this.addReference(e,t))}removeReference(e,t){this.cs(new oB(e,t))}hs(e,t){e.forEach(e=>this.removeReference(e,t))}ls(e){let t=new ri(new rt([])),n=new oB(t,e),r=new oB(t,e+1),i=[];return this.rs.forEachInRange([n,r],e=>{this.cs(e),i.push(e.key)}),i}fs(){this.ns.forEach(e=>this.cs(e))}cs(e){this.ns=this.ns.delete(e),this.rs=this.rs.delete(e)}ds(e){let t=new ri(new rt([])),n=new oB(t,e),r=new oB(t,e+1),i=sN();return this.rs.forEachInRange([n,r],e=>{i=i.add(e.key)}),i}containsKey(e){let t=new oB(e,0),n=this.ns.firstAfterOrEqual(t);return null!==n&&e.isEqual(n.key)}}class oB{constructor(e,t){this.key=e,this._s=t}static ss(e,t){return ri.comparator(e.key,t.key)||n5(e._s,t._s)}static os(e,t){return n5(e._s,t._s)||ri.comparator(e.key,t.key)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oj{constructor(e,t){this.indexManager=e,this.referenceDelegate=t,this.mutationQueue=[],this.ws=1,this.gs=new iS(oB.ss)}checkEmpty(e){return ry.resolve(0===this.mutationQueue.length)}addMutationBatch(e,t,n,r){let i=this.ws;this.ws++,this.mutationQueue.length>0&&this.mutationQueue[this.mutationQueue.length-1];let s=new ak(i,t,n,r);for(let t of(this.mutationQueue.push(s),r))this.gs=this.gs.add(new oB(t.key,i)),this.indexManager.addToCollectionParentIndex(e,t.key.path.popLast());return ry.resolve(s)}lookupMutationBatch(e,t){return ry.resolve(this.ys(t))}getNextMutationBatchAfterBatchId(e,t){let n=this.ps(t+1),r=n<0?0:n;return ry.resolve(this.mutationQueue.length>r?this.mutationQueue[r]:null)}getHighestUnacknowledgedBatchId(){return ry.resolve(0===this.mutationQueue.length?-1:this.ws-1)}getAllMutationBatches(e){return ry.resolve(this.mutationQueue.slice())}getAllMutationBatchesAffectingDocumentKey(e,t){let n=new oB(t,0),r=new oB(t,Number.POSITIVE_INFINITY),i=[];return this.gs.forEachInRange([n,r],e=>{let t=this.ys(e._s);i.push(t)}),ry.resolve(i)}getAllMutationBatchesAffectingDocumentKeys(e,t){let n=new iS(n5);return t.forEach(e=>{let t=new oB(e,0),r=new oB(e,Number.POSITIVE_INFINITY);this.gs.forEachInRange([t,r],e=>{n=n.add(e._s)})}),ry.resolve(this.Is(n))}getAllMutationBatchesAffectingQuery(e,t){let n=t.path,r=n.length+1,i=n;ri.isDocumentKey(i)||(i=i.child(""));let s=new oB(new ri(i),0),a=new iS(n5);return this.gs.forEachWhile(e=>{let t=e.key.path;return!!n.isPrefixOf(t)&&(t.length===r&&(a=a.add(e._s)),!0)},s),ry.resolve(this.Is(a))}Is(e){let t=[];return e.forEach(e=>{let n=this.ys(e);null!==n&&t.push(n)}),t}removeMutationBatch(e,t){0===this.Ts(t.batchId,"removed")||nK(),this.mutationQueue.shift();let n=this.gs;return ry.forEach(t.mutations,r=>{let i=new oB(r.key,t.batchId);return n=n.delete(i),this.referenceDelegate.markPotentiallyOrphaned(e,r.key)}).next(()=>{this.gs=n})}An(e){}containsKey(e,t){let n=new oB(t,0),r=this.gs.firstAfterOrEqual(n);return ry.resolve(t.isEqual(r&&r.key))}performConsistencyCheck(e){return this.mutationQueue.length,ry.resolve()}Ts(e,t){return this.ps(e)}ps(e){return 0===this.mutationQueue.length?0:e-this.mutationQueue[0].batchId}ys(e){let t=this.ps(e);return t<0||t>=this.mutationQueue.length?null:this.mutationQueue[t]}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oz{constructor(e){this.Es=e,this.docs=new iI(ri.comparator),this.size=0}setIndexManager(e){this.indexManager=e}addEntry(e,t){let n=t.key,r=this.docs.get(n),i=r?r.size:0,s=this.Es(t);return this.docs=this.docs.insert(n,{document:t.mutableCopy(),size:s}),this.size+=s-i,this.indexManager.addToCollectionParentIndex(e,n.path.popLast())}removeEntry(e){let t=this.docs.get(e);t&&(this.docs=this.docs.remove(e),this.size-=t.size)}getEntry(e,t){let n=this.docs.get(t);return ry.resolve(n?n.document.mutableCopy():iN.newInvalidDocument(t))}getEntries(e,t){let n=sT;return t.forEach(e=>{let t=this.docs.get(e);n=n.insert(e,t?t.document.mutableCopy():iN.newInvalidDocument(e))}),ry.resolve(n)}getDocumentsMatchingQuery(e,t,n,r){let i=sT,s=t.path,a=new ri(s.child("")),o=this.docs.getIteratorFrom(a);for(;o.hasNext();){let{key:e,value:{document:a}}=o.getNext();if(!s.isPrefixOf(e.path))break;e.path.length>s.length+1||0>=rf(rh(a),n)||(r.has(a.key)||iJ(t,a))&&(i=i.insert(a.key,a.mutableCopy()))}return ry.resolve(i)}getAllFromCollectionGroup(e,t,n,r){nK()}As(e,t){return ry.forEach(this.docs,e=>t(e))}newChangeBuffer(e){return new o$(this)}getSize(e){return ry.resolve(this.size)}}class o$ extends oC{constructor(e){super(),this.Yn=e}applyChanges(e){let t=[];return this.changes.forEach((n,r)=>{r.isValidDocument()?t.push(this.Yn.addEntry(e,r)):this.Yn.removeEntry(n)}),ry.waitFor(t)}getFromCache(e,t){return this.Yn.getEntry(e,t)}getAllFromCache(e,t){return this.Yn.getEntries(e,t)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oG{constructor(e){this.persistence=e,this.Rs=new sI(e=>iO(e),iP),this.lastRemoteSnapshotVersion=n7.min(),this.highestTargetId=0,this.bs=0,this.Ps=new oq,this.targetCount=0,this.vs=oy.Pn()}forEachTarget(e,t){return this.Rs.forEach((e,n)=>t(n)),ry.resolve()}getLastRemoteSnapshotVersion(e){return ry.resolve(this.lastRemoteSnapshotVersion)}getHighestSequenceNumber(e){return ry.resolve(this.bs)}allocateTargetId(e){return this.highestTargetId=this.vs.next(),ry.resolve(this.highestTargetId)}setTargetsMetadata(e,t,n){return n&&(this.lastRemoteSnapshotVersion=n),t>this.bs&&(this.bs=t),ry.resolve()}Dn(e){this.Rs.set(e.target,e);let t=e.targetId;t>this.highestTargetId&&(this.vs=new oy(t),this.highestTargetId=t),e.sequenceNumber>this.bs&&(this.bs=e.sequenceNumber)}addTargetData(e,t){return this.Dn(t),this.targetCount+=1,ry.resolve()}updateTargetData(e,t){return this.Dn(t),ry.resolve()}removeTargetData(e,t){return this.Rs.delete(t.target),this.Ps.ls(t.targetId),this.targetCount-=1,ry.resolve()}removeTargets(e,t,n){let r=0,i=[];return this.Rs.forEach((s,a)=>{a.sequenceNumber<=t&&null===n.get(a.targetId)&&(this.Rs.delete(s),i.push(this.removeMatchingKeysForTargetId(e,a.targetId)),r++)}),ry.waitFor(i).next(()=>r)}getTargetCount(e){return ry.resolve(this.targetCount)}getTargetData(e,t){let n=this.Rs.get(t)||null;return ry.resolve(n)}addMatchingKeys(e,t,n){return this.Ps.us(t,n),ry.resolve()}removeMatchingKeys(e,t,n){this.Ps.hs(t,n);let r=this.persistence.referenceDelegate,i=[];return r&&t.forEach(t=>{i.push(r.markPotentiallyOrphaned(e,t))}),ry.waitFor(i)}removeMatchingKeysForTargetId(e,t){return this.Ps.ls(t),ry.resolve()}getMatchingKeysForTargetId(e,t){let n=this.Ps.ds(t);return ry.resolve(n)}containsKey(e,t){return ry.resolve(this.Ps.containsKey(t))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oK{constructor(e,t){var n;this.Vs={},this.overlays={},this.Ss=new rx(0),this.Ds=!1,this.Ds=!0,this.referenceDelegate=e(this),this.Cs=new oG(this),this.indexManager=new a7,this.remoteDocumentCache=(n=e=>this.referenceDelegate.xs(e),new oz(n)),this.yt=new aN(t),this.Ns=new oF(this.yt)}start(){return Promise.resolve()}shutdown(){return this.Ds=!1,Promise.resolve()}get started(){return this.Ds}setDatabaseDeletedListener(){}setNetworkEnabled(){}getIndexManager(e){return this.indexManager}getDocumentOverlayCache(e){let t=this.overlays[e.toKey()];return t||(t=new oV,this.overlays[e.toKey()]=t),t}getMutationQueue(e,t){let n=this.Vs[e.toKey()];return n||(n=new oj(t,this.referenceDelegate),this.Vs[e.toKey()]=n),n}getTargetCache(){return this.Cs}getRemoteDocumentCache(){return this.remoteDocumentCache}getBundleCache(){return this.Ns}runTransaction(e,t,n){nj("MemoryPersistence","Starting transaction:",e);let r=new oW(this.Ss.next());return this.referenceDelegate.ks(),n(r).next(e=>this.referenceDelegate.Os(r).next(()=>e)).toPromise().then(e=>(r.raiseOnCommittedEvent(),e))}Ms(e,t){return ry.or(Object.values(this.Vs).map(n=>()=>n.containsKey(e,t)))}}class oW extends rm{constructor(e){super(),this.currentSequenceNumber=e}}class oH{constructor(e){this.persistence=e,this.Fs=new oq,this.$s=null}static Bs(e){return new oH(e)}get Ls(){if(this.$s)return this.$s;throw nK()}addReference(e,t,n){return this.Fs.addReference(n,t),this.Ls.delete(n.toString()),ry.resolve()}removeReference(e,t,n){return this.Fs.removeReference(n,t),this.Ls.add(n.toString()),ry.resolve()}markPotentiallyOrphaned(e,t){return this.Ls.add(t.toString()),ry.resolve()}removeTarget(e,t){this.Fs.ls(t.targetId).forEach(e=>this.Ls.add(e.toString()));let n=this.persistence.getTargetCache();return n.getMatchingKeysForTargetId(e,t.targetId).next(e=>{e.forEach(e=>this.Ls.add(e.toString()))}).next(()=>n.removeTargetData(e,t))}ks(){this.$s=new Set}Os(e){let t=this.persistence.getRemoteDocumentCache().newChangeBuffer();return ry.forEach(this.Ls,n=>{let r=ri.fromPath(n);return this.qs(e,r).next(e=>{e||t.removeEntry(r,n7.min())})}).next(()=>(this.$s=null,t.apply(e)))}updateLimboDocument(e,t){return this.qs(e,t).next(e=>{e?this.Ls.delete(t.toString()):this.Ls.add(t.toString())})}xs(e){return 0}qs(e,t){return ry.or([()=>ry.resolve(this.Fs.containsKey(t)),()=>this.persistence.getTargetCache().containsKey(e,t),()=>this.persistence.Ms(e,t)])}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oQ{constructor(e){this.yt=e}$(e,t,n,r){let i=new rv("createOrUpgrade",t);n<1&&r>=1&&(function(e){e.createObjectStore("owner")}(e),e.createObjectStore("mutationQueues",{keyPath:"userId"}),e.createObjectStore("mutations",{keyPath:"batchId",autoIncrement:!0}).createIndex("userMutationsIndex",ai,{unique:!0}),e.createObjectStore("documentMutations"),oY(e),function(e){e.createObjectStore("remoteDocuments")}(e));let s=ry.resolve();return n<3&&r>=3&&(0!==n&&(e.deleteObjectStore("targetDocuments"),e.deleteObjectStore("targets"),e.deleteObjectStore("targetGlobal"),oY(e)),s=s.next(()=>(function(e){let t=e.store("targetGlobal"),n={highestTargetId:0,highestListenSequenceNumber:0,lastRemoteSnapshotVersion:n7.min().toTimestamp(),targetCount:0};return t.put("targetGlobalKey",n)})(i))),n<4&&r>=4&&(0!==n&&(s=s.next(()=>i.store("mutations").W().next(t=>{e.deleteObjectStore("mutations"),e.createObjectStore("mutations",{keyPath:"batchId",autoIncrement:!0}).createIndex("userMutationsIndex",ai,{unique:!0});let n=i.store("mutations"),r=t.map(e=>n.put(e));return ry.waitFor(r)}))),s=s.next(()=>{!function(e){e.createObjectStore("clientMetadata",{keyPath:"clientId"})}(e)})),n<5&&r>=5&&(s=s.next(()=>this.Us(i))),n<6&&r>=6&&(s=s.next(()=>((function(e){e.createObjectStore("remoteDocumentGlobal")})(e),this.Ks(i)))),n<7&&r>=7&&(s=s.next(()=>this.Gs(i))),n<8&&r>=8&&(s=s.next(()=>this.Qs(e,i))),n<9&&r>=9&&(s=s.next(()=>{e.objectStoreNames.contains("remoteDocumentChanges")&&e.deleteObjectStore("remoteDocumentChanges")})),n<10&&r>=10&&(s=s.next(()=>this.js(i))),n<11&&r>=11&&(s=s.next(()=>{(function(e){e.createObjectStore("bundles",{keyPath:"bundleId"})})(e),function(e){e.createObjectStore("namedQueries",{keyPath:"name"})}(e)})),n<12&&r>=12&&(s=s.next(()=>{!function(e){let t=e.createObjectStore("documentOverlays",{keyPath:ay});t.createIndex("collectionPathOverlayIndex",av,{unique:!1}),t.createIndex("collectionGroupOverlayIndex",aw,{unique:!1})}(e)})),n<13&&r>=13&&(s=s.next(()=>(function(e){let t=e.createObjectStore("remoteDocumentsV14",{keyPath:aa});t.createIndex("documentKeyIndex",ao),t.createIndex("collectionGroupIndex",al)})(e)).next(()=>this.Ws(e,i)).next(()=>e.deleteObjectStore("remoteDocuments"))),n<14&&r>=14&&(s=s.next(()=>this.zs(e,i))),n<15&&r>=15&&(s=s.next(()=>{e.createObjectStore("indexConfiguration",{keyPath:"indexId",autoIncrement:!0}).createIndex("collectionGroupIndex","collectionGroup",{unique:!1}),e.createObjectStore("indexState",{keyPath:af}).createIndex("sequenceNumberIndex",ap,{unique:!1}),e.createObjectStore("indexEntries",{keyPath:am}).createIndex("documentKeyIndex",ag,{unique:!1})})),s}Ks(e){let t=0;return e.store("remoteDocuments").Z((e,n)=>{t+=oh(n)}).next(()=>{let n={byteSize:t};return e.store("remoteDocumentGlobal").put("remoteDocumentGlobalKey",n)})}Us(e){let t=e.store("mutationQueues"),n=e.store("mutations");return t.W().next(t=>ry.forEach(t,t=>{let r=IDBKeyRange.bound([t.userId,-1],[t.userId,t.lastAcknowledgedBatchId]);return n.W("userMutationsIndex",r).next(n=>ry.forEach(n,n=>{n.userId===t.userId||nK();let r=aL(this.yt,n);return oc(e,t.userId,r).next(()=>{})}))}))}Gs(e){let t=e.store("targetDocuments"),n=e.store("remoteDocuments");return e.store("targetGlobal").get("targetGlobalKey").next(e=>{let r=[];return n.Z((n,i)=>{let s=new rt(n),a=[0,an(s)];r.push(t.get(a).next(n=>n?ry.resolve():t.put({targetId:0,path:an(s),sequenceNumber:e.highestListenSequenceNumber})))}).next(()=>ry.waitFor(r))})}Qs(e,t){e.createObjectStore("collectionParents",{keyPath:ad});let n=t.store("collectionParents"),r=new oe,i=e=>{if(r.add(e)){let t=e.lastSegment(),r=e.popLast();return n.put({collectionId:t,parent:an(r)})}};return t.store("remoteDocuments").Z({X:!0},(e,t)=>{let n=new rt(e);return i(n.popLast())}).next(()=>t.store("documentMutations").Z({X:!0},([e,t,n],r)=>{let s=ar(t);return i(s.popLast())}))}js(e){let t=e.store("targets");return t.Z((e,n)=>{let r=aM(n),i=aU(this.yt,r);return t.put(i)})}Ws(e,t){let n=t.store("remoteDocuments"),r=[];return n.Z((e,n)=>{let i=t.store("remoteDocumentsV14"),s=(n.document?new ri(rt.fromString(n.document.name).popFirst(5)):n.noDocument?ri.fromSegments(n.noDocument.path):n.unknownDocument?ri.fromSegments(n.unknownDocument.path):nK()).path.toArray(),a={prefixPath:s.slice(0,s.length-2),collectionGroup:s[s.length-2],documentId:s[s.length-1],readTime:n.readTime||[0,0],unknownDocument:n.unknownDocument,noDocument:n.noDocument,document:n.document,hasCommittedMutations:!!n.hasCommittedMutations};r.push(i.put(a))}).next(()=>ry.waitFor(r))}zs(e,t){var n;let r=t.store("mutations"),i=(n=this.yt,new ox(n)),s=new oK(oH.Bs,this.yt.ie);return r.W().next(e=>{let n=new Map;return e.forEach(e=>{var t;let r=null!==(t=n.get(e.userId))&&void 0!==t?t:sN();aL(this.yt,e).keys().forEach(e=>r=r.add(e)),n.set(e.userId,r)}),ry.forEach(n,(e,n)=>{let r=new nU(n),a=aG.re(this.yt,r),o=s.getIndexManager(r),l=od.re(r,this.yt,o,s.referenceDelegate);return new oU(i,l,a,o).recalculateAndSaveOverlaysForDocumentKeys(new aE(t,rx.at),e).next()})})}}function oY(e){e.createObjectStore("targetDocuments",{keyPath:ac}).createIndex("documentTargetsIndex",ah,{unique:!0}),e.createObjectStore("targets",{keyPath:"targetId"}).createIndex("queryTargetsIndex",au,{unique:!0}),e.createObjectStore("targetGlobal")}let oX="Failed to obtain exclusive access to the persistence layer. To allow shared access, multi-tab synchronization has to be enabled in all tabs. If you are using `experimentalForceOwningTab:true`, make sure that only one tab has persistence enabled at any given time.";class oJ{constructor(e,t,n,r,i,s,a,o,l,u,c=15){var h;if(this.allowTabSynchronization=e,this.persistenceKey=t,this.clientId=n,this.Hs=i,this.window=s,this.document=a,this.Js=l,this.Ys=u,this.Xs=c,this.Ss=null,this.Ds=!1,this.isPrimary=!1,this.networkEnabled=!0,this.Zs=null,this.inForeground=!1,this.ti=null,this.ei=null,this.ni=Number.NEGATIVE_INFINITY,this.si=e=>Promise.resolve(),!oJ.C())throw new nQ(nH.UNIMPLEMENTED,"This platform is either missing IndexedDB or is known to have an incomplete implementation. Offline persistence has been disabled.");this.referenceDelegate=new ok(this,r),this.ii=t+"main",this.yt=new aN(o),this.ri=new rw(this.ii,this.Xs,new oQ(this.yt)),this.Cs=new ov(this.referenceDelegate,this.yt),this.remoteDocumentCache=(h=this.yt,new ox(h)),this.Ns=new aj,this.window&&this.window.localStorage?this.oi=this.window.localStorage:(this.oi=null,!1===u&&nz("IndexedDbPersistence","LocalStorage is unavailable. As a result, persistence may not work reliably. In particular enablePersistence() could fail immediately after refreshing the page."))}start(){return this.ui().then(()=>{if(!this.isPrimary&&!this.allowTabSynchronization)throw new nQ(nH.FAILED_PRECONDITION,oX);return this.ci(),this.ai(),this.hi(),this.runTransaction("getHighestListenSequenceNumber","readonly",e=>this.Cs.getHighestSequenceNumber(e))}).then(e=>{this.Ss=new rx(e,this.Js)}).then(()=>{this.Ds=!0}).catch(e=>(this.ri&&this.ri.close(),Promise.reject(e)))}li(e){return this.si=async t=>{if(this.started)return e(t)},e(this.isPrimary)}setDatabaseDeletedListener(e){this.ri.L(async t=>{null===t.newVersion&&await e()})}setNetworkEnabled(e){this.networkEnabled!==e&&(this.networkEnabled=e,this.Hs.enqueueAndForget(async()=>{this.started&&await this.ui()}))}ui(){return this.runTransaction("updateClientMetadataAndTryBecomePrimary","readwrite",e=>o0(e).put({clientId:this.clientId,updateTimeMs:Date.now(),networkEnabled:this.networkEnabled,inForeground:this.inForeground}).next(()=>{if(this.isPrimary)return this.fi(e).next(e=>{e||(this.isPrimary=!1,this.Hs.enqueueRetryable(()=>this.si(!1)))})}).next(()=>this.di(e)).next(t=>this.isPrimary&&!t?this._i(e).next(()=>!1):!!t&&this.wi(e).next(()=>!0))).catch(e=>{if(rI(e))return nj("IndexedDbPersistence","Failed to extend owner lease: ",e),this.isPrimary;if(!this.allowTabSynchronization)throw e;return nj("IndexedDbPersistence","Releasing owner lease after error during lease refresh",e),!1}).then(e=>{this.isPrimary!==e&&this.Hs.enqueueRetryable(()=>this.si(e)),this.isPrimary=e})}fi(e){return oZ(e).get("owner").next(e=>ry.resolve(this.mi(e)))}gi(e){return o0(e).delete(this.clientId)}async yi(){if(this.isPrimary&&!this.pi(this.ni,18e5)){this.ni=Date.now();let e=await this.runTransaction("maybeGarbageCollectMultiClientState","readwrite-primary",e=>{let t=aS(e,"clientMetadata");return t.W().next(e=>{let n=this.Ii(e,18e5),r=e.filter(e=>-1===n.indexOf(e));return ry.forEach(r,e=>t.delete(e.clientId)).next(()=>r)})}).catch(()=>[]);if(this.oi)for(let t of e)this.oi.removeItem(this.Ti(t.clientId))}}hi(){this.ei=this.Hs.enqueueAfterDelay("client_metadata_refresh",4e3,()=>this.ui().then(()=>this.yi()).then(()=>this.hi()))}mi(e){return!!e&&e.ownerId===this.clientId}di(e){return this.Ys?ry.resolve(!0):oZ(e).get("owner").next(t=>{if(null!==t&&this.pi(t.leaseTimestampMs,5e3)&&!this.Ei(t.ownerId)){if(this.mi(t)&&this.networkEnabled)return!0;if(!this.mi(t)){if(!t.allowTabSynchronization)throw new nQ(nH.FAILED_PRECONDITION,oX);return!1}}return!(!this.networkEnabled||!this.inForeground)||o0(e).W().next(e=>void 0===this.Ii(e,5e3).find(e=>{if(this.clientId!==e.clientId){let t=!this.networkEnabled&&e.networkEnabled,n=!this.inForeground&&e.inForeground,r=this.networkEnabled===e.networkEnabled;if(t||n&&r)return!0}return!1}))}).next(e=>(this.isPrimary!==e&&nj("IndexedDbPersistence",`Client ${e?"is":"is not"} eligible for a primary lease.`),e))}async shutdown(){this.Ds=!1,this.Ai(),this.ei&&(this.ei.cancel(),this.ei=null),this.Ri(),this.bi(),await this.ri.runTransaction("shutdown","readwrite",["owner","clientMetadata"],e=>{let t=new aE(e,rx.at);return this._i(t).next(()=>this.gi(t))}),this.ri.close(),this.Pi()}Ii(e,t){return e.filter(e=>this.pi(e.updateTimeMs,t)&&!this.Ei(e.clientId))}vi(){return this.runTransaction("getActiveClients","readonly",e=>o0(e).W().next(e=>this.Ii(e,18e5).map(e=>e.clientId)))}get started(){return this.Ds}getMutationQueue(e,t){return od.re(e,this.yt,t,this.referenceDelegate)}getTargetCache(){return this.Cs}getRemoteDocumentCache(){return this.remoteDocumentCache}getIndexManager(e){return new on(e,this.yt.ie.databaseId)}getDocumentOverlayCache(e){return aG.re(this.yt,e)}getBundleCache(){return this.Ns}runTransaction(e,t,n){var r;let i;nj("IndexedDbPersistence","Starting transaction:",e);let s=15===(r=this.Xs)?aT:14===r?aI:13===r?aI:12===r?ab:11===r?a_:void nK();return this.ri.runTransaction(e,"readonly"===t?"readonly":"readwrite",s,r=>(i=new aE(r,this.Ss?this.Ss.next():rx.at),"readwrite-primary"===t?this.fi(i).next(e=>!!e||this.di(i)).next(t=>{if(!t)throw nz(`Failed to obtain primary lease for action '${e}'.`),this.isPrimary=!1,this.Hs.enqueueRetryable(()=>this.si(!1)),new nQ(nH.FAILED_PRECONDITION,rp);return n(i)}).next(e=>this.wi(i).next(()=>e)):this.Vi(i).next(()=>n(i)))).then(e=>(i.raiseOnCommittedEvent(),e))}Vi(e){return oZ(e).get("owner").next(e=>{if(null!==e&&this.pi(e.leaseTimestampMs,5e3)&&!this.Ei(e.ownerId)&&!this.mi(e)&&!(this.Ys||this.allowTabSynchronization&&e.allowTabSynchronization))throw new nQ(nH.FAILED_PRECONDITION,oX)})}wi(e){let t={ownerId:this.clientId,allowTabSynchronization:this.allowTabSynchronization,leaseTimestampMs:Date.now()};return oZ(e).put("owner",t)}static C(){return rw.C()}_i(e){let t=oZ(e);return t.get("owner").next(e=>this.mi(e)?(nj("IndexedDbPersistence","Releasing primary lease."),t.delete("owner")):ry.resolve())}pi(e,t){let n=Date.now();return!(e<n-t)&&(!(e>n)||(nz(`Detected an update time that is in the future: ${e} > ${n}`),!1))}ci(){null!==this.document&&"function"==typeof this.document.addEventListener&&(this.ti=()=>{this.Hs.enqueueAndForget(()=>(this.inForeground="visible"===this.document.visibilityState,this.ui()))},this.document.addEventListener("visibilitychange",this.ti),this.inForeground="visible"===this.document.visibilityState)}Ri(){this.ti&&(this.document.removeEventListener("visibilitychange",this.ti),this.ti=null)}ai(){var e;"function"==typeof(null===(e=this.window)||void 0===e?void 0:e.addEventListener)&&(this.Zs=()=>{this.Ai(),(0,p.G6)()&&navigator.appVersion.match(/Version\/1[45]/)&&this.Hs.enterRestrictedMode(!0),this.Hs.enqueueAndForget(()=>this.shutdown())},this.window.addEventListener("pagehide",this.Zs))}bi(){this.Zs&&(this.window.removeEventListener("pagehide",this.Zs),this.Zs=null)}Ei(e){var t;try{let n=null!==(null===(t=this.oi)||void 0===t?void 0:t.getItem(this.Ti(e)));return nj("IndexedDbPersistence",`Client '${e}' ${n?"is":"is not"} zombied in LocalStorage`),n}catch(e){return nz("IndexedDbPersistence","Failed to get zombied client id.",e),!1}}Ai(){if(this.oi)try{this.oi.setItem(this.Ti(this.clientId),String(Date.now()))}catch(e){nz("Failed to set zombie client id.",e)}}Pi(){if(this.oi)try{this.oi.removeItem(this.Ti(this.clientId))}catch(e){}}Ti(e){return`firestore_zombie_${this.persistenceKey}_${e}`}}function oZ(e){return aS(e,"owner")}function o0(e){return aS(e,"clientMetadata")}function o1(e,t){let n=e.projectId;return e.isDefaultDatabase||(n+="."+e.database),"firestore/"+t+"/"+n+"/"}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class o2{constructor(e,t,n,r){this.targetId=e,this.fromCache=t,this.Si=n,this.Di=r}static Ci(e,t){let n=sN(),r=sN();for(let e of t.docChanges)switch(e.type){case 0:n=n.add(e.doc.key);break;case 1:r=r.add(e.doc.key)}return new o2(e,t.fromCache,n,r)}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class o3{constructor(){this.xi=!1}initialize(e,t){this.Ni=e,this.indexManager=t,this.xi=!0}getDocumentsMatchingQuery(e,t,n,r){return this.ki(e,t).next(i=>i||this.Oi(e,t,r,n)).next(n=>n||this.Mi(e,t))}ki(e,t){if(iB(t))return ry.resolve(null);let n=iK(t);return this.indexManager.getIndexType(e,n).next(r=>0===r?null:(null!==t.limit&&1===r&&(n=iK(t=iH(t,null,"F"))),this.indexManager.getDocumentsMatchingTarget(e,n).next(r=>{let i=sN(...r);return this.Ni.getDocuments(e,i).next(r=>this.indexManager.getMinOffset(e,n).next(n=>{let s=this.Fi(t,r);return this.$i(t,s,i,n.readTime)?this.ki(e,iH(t,null,"F")):this.Bi(e,s,t,n)}))})))}Oi(e,t,n,r){return iB(t)||r.isEqual(n7.min())?this.Mi(e,t):this.Ni.getDocuments(e,n).next(i=>{let s=this.Fi(t,i);return this.$i(t,s,n,r)?this.Mi(e,t):(nq()<=f.in.DEBUG&&nj("QueryEngine","Re-using previous result from %s to execute query: %s",r.toString(),iX(t)),this.Bi(e,s,t,rc(r,-1)))})}Fi(e,t){let n=new iS(i0(e));return t.forEach((t,r)=>{iJ(e,r)&&(n=n.add(r))}),n}$i(e,t,n,r){if(null===e.limit)return!1;if(n.size!==t.size)return!0;let i="F"===e.limitType?t.last():t.first();return!!i&&(i.hasPendingWrites||i.version.compareTo(r)>0)}Mi(e,t){return nq()<=f.in.DEBUG&&nj("QueryEngine","Using full collection scan to execute query:",iX(t)),this.Ni.getDocumentsMatchingQuery(e,t,rd.min())}Bi(e,t,n,r){return this.Ni.getDocumentsMatchingQuery(e,n,r).next(e=>(t.forEach(t=>{e=e.insert(t.key,t)}),e))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class o4{constructor(e,t,n,r){this.persistence=e,this.Li=t,this.yt=r,this.qi=new iI(n5),this.Ui=new sI(e=>iO(e),iP),this.Ki=new Map,this.Gi=e.getRemoteDocumentCache(),this.Cs=e.getTargetCache(),this.Ns=e.getBundleCache(),this.Qi(n)}Qi(e){this.documentOverlayCache=this.persistence.getDocumentOverlayCache(e),this.indexManager=this.persistence.getIndexManager(e),this.mutationQueue=this.persistence.getMutationQueue(e,this.indexManager),this.localDocuments=new oU(this.Gi,this.mutationQueue,this.documentOverlayCache,this.indexManager),this.Gi.setIndexManager(this.indexManager),this.Li.initialize(this.localDocuments,this.indexManager)}collectGarbage(e){return this.persistence.runTransaction("Collect garbage","readwrite-primary",t=>e.collect(t,this.qi))}}async function o6(e,t){return await e.persistence.runTransaction("Handle user change","readonly",n=>{let r;return e.mutationQueue.getAllMutationBatches(n).next(i=>(r=i,e.Qi(t),e.mutationQueue.getAllMutationBatches(n))).next(t=>{let i=[],s=[],a=sN();for(let e of r)for(let t of(i.push(e.batchId),e.mutations))a=a.add(t.key);for(let e of t)for(let t of(s.push(e.batchId),e.mutations))a=a.add(t.key);return e.localDocuments.getDocuments(n,a).next(e=>({ji:e,removedBatchIds:i,addedBatchIds:s}))})})}function o5(e){return e.persistence.runTransaction("Get last remote snapshot version","readonly",t=>e.Cs.getLastRemoteSnapshotVersion(t))}function o9(e,t,n){let r=sN(),i=sN();return n.forEach(e=>r=r.add(e)),t.getEntries(e,r).next(e=>{let r=sT;return n.forEach((n,s)=>{let a=e.get(n);s.isFoundDocument()!==a.isFoundDocument()&&(i=i.add(n)),s.isNoDocument()&&s.version.isEqual(n7.min())?(t.removeEntry(n,s.readTime),r=r.insert(n,s)):!a.isValidDocument()||s.version.compareTo(a.version)>0||0===s.version.compareTo(a.version)&&a.hasPendingWrites?(t.addEntry(s),r=r.insert(n,s)):nj("LocalStore","Ignoring outdated watch update for ",n,". Current version:",a.version," Watch version:",s.version)}),{Wi:r,zi:i}})}function o8(e,t){let n=e;return n.persistence.runTransaction("Allocate target","readwrite",e=>{let r;return n.Cs.getTargetData(e,t).next(i=>i?(r=i,ry.resolve(r)):n.Cs.allocateTargetId(e).next(i=>(r=new ax(t,i,0,e.currentSequenceNumber),n.Cs.addTargetData(e,r).next(()=>r))))}).then(e=>{let r=n.qi.get(e.targetId);return(null===r||e.snapshotVersion.compareTo(r.snapshotVersion)>0)&&(n.qi=n.qi.insert(e.targetId,e),n.Ui.set(t,e.targetId)),e})}async function o7(e,t,n){let r=e,i=r.qi.get(t);try{n||await r.persistence.runTransaction("Release target",n?"readwrite":"readwrite-primary",e=>r.persistence.referenceDelegate.removeTarget(e,i))}catch(e){if(!rI(e))throw e;nj("LocalStore",`Failed to update sequence numbers for target ${t}: ${e}`)}r.qi=r.qi.remove(t),r.Ui.delete(i.target)}function le(e,t,n){let r=n7.min(),i=sN();return e.persistence.runTransaction("Execute query","readonly",s=>(function(e,t,n){let r=e.Ui.get(n);return void 0!==r?ry.resolve(e.qi.get(r)):e.Cs.getTargetData(t,n)})(e,s,iK(t)).next(t=>{if(t)return r=t.lastLimboFreeSnapshotVersion,e.Cs.getMatchingKeysForTargetId(s,t.targetId).next(e=>{i=e})}).next(()=>e.Li.getDocumentsMatchingQuery(s,t,n?r:n7.min(),n?i:sN())).next(n=>(lr(e,iZ(t),n),{documents:n,Hi:i})))}function lt(e,t){let n=e.Cs,r=e.qi.get(t);return r?Promise.resolve(r.target):e.persistence.runTransaction("Get target data","readonly",e=>n.ne(e,t).next(e=>e?e.target:null))}function ln(e,t){let n=e.Ki.get(t)||n7.min();return e.persistence.runTransaction("Get new document changes","readonly",r=>e.Gi.getAllFromCollectionGroup(r,t,rc(n,-1),Number.MAX_SAFE_INTEGER)).then(n=>(lr(e,t,n),n))}function lr(e,t,n){let r=e.Ki.get(t)||n7.min();n.forEach((e,t)=>{t.readTime.compareTo(r)>0&&(r=t.readTime)}),e.Ki.set(t,r)}async function li(e,t,n,r){let i=sN(),s=sT;for(let e of n){let n=t.Ji(e.metadata.name);e.document&&(i=i.add(n));let r=t.Yi(e);r.setReadTime(t.Xi(e.metadata.readTime)),s=s.insert(n,r)}let a=e.Gi.newChangeBuffer({trackRemovals:!0}),o=await o8(e,iK(iq(rt.fromString(`__bundle__/docs/${r}`))));return e.persistence.runTransaction("Apply bundle documents","readwrite",t=>o9(t,a,s).next(e=>(a.apply(t),e)).next(n=>e.Cs.removeMatchingKeysForTargetId(t,o.targetId).next(()=>e.Cs.addMatchingKeys(t,i,o.targetId)).next(()=>e.localDocuments.getLocalViewOfDocuments(t,n.Wi,n.zi)).next(()=>n.Wi)))}async function ls(e,t,n=sN()){let r=await o8(e,iK(aF(t.bundledQuery))),i=e;return i.persistence.runTransaction("Save named query","readwrite",e=>{let s=sW(t.readTime);if(r.snapshotVersion.compareTo(s)>=0)return i.Ns.saveNamedQuery(e,t);let a=r.withResumeToken(rV.EMPTY_BYTE_STRING,s);return i.qi=i.qi.insert(a.targetId,a),i.Cs.updateTargetData(e,a).next(()=>i.Cs.removeMatchingKeysForTargetId(e,r.targetId)).next(()=>i.Cs.addMatchingKeys(e,n,r.targetId)).next(()=>i.Ns.saveNamedQuery(e,t))})}function la(e,t){return`firestore_clients_${e}_${t}`}function lo(e,t,n){let r=`firestore_mutations_${e}_${n}`;return t.isAuthenticated()&&(r+=`_${t.uid}`),r}function ll(e,t){return`firestore_targets_${e}_${t}`}class lu{constructor(e,t,n,r){this.user=e,this.batchId=t,this.state=n,this.error=r}static Zi(e,t,n){let r=JSON.parse(n),i,s="object"==typeof r&&-1!==["pending","acknowledged","rejected"].indexOf(r.state)&&(void 0===r.error||"object"==typeof r.error);return s&&r.error&&(s="string"==typeof r.error.message&&"string"==typeof r.error.code)&&(i=new nQ(r.error.code,r.error.message)),s?new lu(e,t,r.state,i):(nz("SharedClientState",`Failed to parse mutation state for ID '${t}': ${n}`),null)}tr(){let e={state:this.state,updateTimeMs:Date.now()};return this.error&&(e.error={code:this.error.code,message:this.error.message}),JSON.stringify(e)}}class lc{constructor(e,t,n){this.targetId=e,this.state=t,this.error=n}static Zi(e,t){let n=JSON.parse(t),r,i="object"==typeof n&&-1!==["not-current","current","rejected"].indexOf(n.state)&&(void 0===n.error||"object"==typeof n.error);return i&&n.error&&(i="string"==typeof n.error.message&&"string"==typeof n.error.code)&&(r=new nQ(n.error.code,n.error.message)),i?new lc(e,n.state,r):(nz("SharedClientState",`Failed to parse target state for ID '${e}': ${t}`),null)}tr(){let e={state:this.state,updateTimeMs:Date.now()};return this.error&&(e.error={code:this.error.code,message:this.error.message}),JSON.stringify(e)}}class lh{constructor(e,t){this.clientId=e,this.activeTargetIds=t}static Zi(e,t){let n=JSON.parse(t),r="object"==typeof n&&n.activeTargetIds instanceof Array,i=sR;for(let e=0;r&&e<n.activeTargetIds.length;++e)r=rU(n.activeTargetIds[e]),i=i.add(n.activeTargetIds[e]);return r?new lh(e,i):(nz("SharedClientState",`Failed to parse client data for instance '${e}': ${t}`),null)}}class ld{constructor(e,t){this.clientId=e,this.onlineState=t}static Zi(e){let t=JSON.parse(e);return"object"==typeof t&&-1!==["Unknown","Online","Offline"].indexOf(t.onlineState)&&"string"==typeof t.clientId?new ld(t.clientId,t.onlineState):(nz("SharedClientState",`Failed to parse online state: ${e}`),null)}}class lf{constructor(){this.activeTargetIds=sR}er(e){this.activeTargetIds=this.activeTargetIds.add(e)}nr(e){this.activeTargetIds=this.activeTargetIds.delete(e)}tr(){let e={activeTargetIds:this.activeTargetIds.toArray(),updateTimeMs:Date.now()};return JSON.stringify(e)}}class lp{constructor(e,t,n,r,i){this.window=e,this.Hs=t,this.persistenceKey=n,this.sr=r,this.syncEngine=null,this.onlineStateHandler=null,this.sequenceNumberHandler=null,this.ir=this.rr.bind(this),this.ur=new iI(n5),this.started=!1,this.cr=[];let s=n.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");this.storage=this.window.localStorage,this.currentUser=i,this.ar=la(this.persistenceKey,this.sr),this.hr=`firestore_sequence_number_${this.persistenceKey}`,this.ur=this.ur.insert(this.sr,new lf),this.lr=RegExp(`^firestore_clients_${s}_([^_]*)$`),this.dr=RegExp(`^firestore_mutations_${s}_(\\d+)(?:_(.*))?$`),this._r=RegExp(`^firestore_targets_${s}_(\\d+)$`),this.wr=`firestore_online_state_${this.persistenceKey}`,this.mr=`firestore_bundle_loaded_v2_${this.persistenceKey}`,this.window.addEventListener("storage",this.ir)}static C(e){return!(!e||!e.localStorage)}async start(){let e=await this.syncEngine.vi();for(let t of e){if(t===this.sr)continue;let e=this.getItem(la(this.persistenceKey,t));if(e){let n=lh.Zi(t,e);n&&(this.ur=this.ur.insert(n.clientId,n))}}this.gr();let t=this.storage.getItem(this.wr);if(t){let e=this.yr(t);e&&this.pr(e)}for(let e of this.cr)this.rr(e);this.cr=[],this.window.addEventListener("pagehide",()=>this.shutdown()),this.started=!0}writeSequenceNumber(e){this.setItem(this.hr,JSON.stringify(e))}getAllActiveQueryTargets(){return this.Ir(this.ur)}isActiveQueryTarget(e){let t=!1;return this.ur.forEach((n,r)=>{r.activeTargetIds.has(e)&&(t=!0)}),t}addPendingMutation(e){this.Tr(e,"pending")}updateMutationState(e,t,n){this.Tr(e,t,n),this.Er(e)}addLocalQueryTarget(e){let t="not-current";if(this.isActiveQueryTarget(e)){let n=this.storage.getItem(ll(this.persistenceKey,e));if(n){let r=lc.Zi(e,n);r&&(t=r.state)}}return this.Ar.er(e),this.gr(),t}removeLocalQueryTarget(e){this.Ar.nr(e),this.gr()}isLocalQueryTarget(e){return this.Ar.activeTargetIds.has(e)}clearQueryState(e){this.removeItem(ll(this.persistenceKey,e))}updateQueryState(e,t,n){this.Rr(e,t,n)}handleUserChange(e,t,n){t.forEach(e=>{this.Er(e)}),this.currentUser=e,n.forEach(e=>{this.addPendingMutation(e)})}setOnlineState(e){this.br(e)}notifyBundleLoaded(e){this.Pr(e)}shutdown(){this.started&&(this.window.removeEventListener("storage",this.ir),this.removeItem(this.ar),this.started=!1)}getItem(e){let t=this.storage.getItem(e);return nj("SharedClientState","READ",e,t),t}setItem(e,t){nj("SharedClientState","SET",e,t),this.storage.setItem(e,t)}removeItem(e){nj("SharedClientState","REMOVE",e),this.storage.removeItem(e)}rr(e){if(e.storageArea===this.storage){if(nj("SharedClientState","EVENT",e.key,e.newValue),e.key===this.ar)return void nz("Received WebStorage notification for local change. Another client might have garbage-collected our state");this.Hs.enqueueRetryable(async()=>{if(this.started){if(null!==e.key){if(this.lr.test(e.key)){if(null==e.newValue){let t=this.vr(e.key);return this.Vr(t,null)}{let t=this.Sr(e.key,e.newValue);if(t)return this.Vr(t.clientId,t)}}else if(this.dr.test(e.key)){if(null!==e.newValue){let t=this.Dr(e.key,e.newValue);if(t)return this.Cr(t)}}else if(this._r.test(e.key)){if(null!==e.newValue){let t=this.Nr(e.key,e.newValue);if(t)return this.kr(t)}}else if(e.key===this.wr){if(null!==e.newValue){let t=this.yr(e.newValue);if(t)return this.pr(t)}}else if(e.key===this.hr){let t=function(e){let t=rx.at;if(null!=e)try{let n=JSON.parse(e);"number"==typeof n||nK(),t=n}catch(e){nz("SharedClientState","Failed to read sequence number from WebStorage",e)}return t}(e.newValue);t!==rx.at&&this.sequenceNumberHandler(t)}else if(e.key===this.mr){let t=this.Or(e.newValue);await Promise.all(t.map(e=>this.syncEngine.Mr(e)))}}}else this.cr.push(e)})}}get Ar(){return this.ur.get(this.sr)}gr(){this.setItem(this.ar,this.Ar.tr())}Tr(e,t,n){let r=new lu(this.currentUser,e,t,n),i=lo(this.persistenceKey,this.currentUser,e);this.setItem(i,r.tr())}Er(e){let t=lo(this.persistenceKey,this.currentUser,e);this.removeItem(t)}br(e){let t={clientId:this.sr,onlineState:e};this.storage.setItem(this.wr,JSON.stringify(t))}Rr(e,t,n){let r=ll(this.persistenceKey,e),i=new lc(e,t,n);this.setItem(r,i.tr())}Pr(e){let t=JSON.stringify(Array.from(e));this.setItem(this.mr,t)}vr(e){let t=this.lr.exec(e);return t?t[1]:null}Sr(e,t){let n=this.vr(e);return lh.Zi(n,t)}Dr(e,t){let n=this.dr.exec(e),r=Number(n[1]),i=void 0!==n[2]?n[2]:null;return lu.Zi(new nU(i),r,t)}Nr(e,t){let n=this._r.exec(e),r=Number(n[1]);return lc.Zi(r,t)}yr(e){return ld.Zi(e)}Or(e){return JSON.parse(e)}async Cr(e){if(e.user.uid===this.currentUser.uid)return this.syncEngine.Fr(e.batchId,e.state,e.error);nj("SharedClientState",`Ignoring mutation for non-active user ${e.user.uid}`)}kr(e){return this.syncEngine.$r(e.targetId,e.state,e.error)}Vr(e,t){let n=t?this.ur.insert(e,t):this.ur.remove(e),r=this.Ir(this.ur),i=this.Ir(n),s=[],a=[];return i.forEach(e=>{r.has(e)||s.push(e)}),r.forEach(e=>{i.has(e)||a.push(e)}),this.syncEngine.Br(s,a).then(()=>{this.ur=n})}pr(e){this.ur.get(e.clientId)&&this.onlineStateHandler(e.onlineState)}Ir(e){let t=sR;return e.forEach((e,n)=>{t=t.unionWith(n.activeTargetIds)}),t}}class lm{constructor(){this.Lr=new lf,this.qr={},this.onlineStateHandler=null,this.sequenceNumberHandler=null}addPendingMutation(e){}updateMutationState(e,t,n){}addLocalQueryTarget(e){return this.Lr.er(e),this.qr[e]||"not-current"}updateQueryState(e,t,n){this.qr[e]=t}removeLocalQueryTarget(e){this.Lr.nr(e)}isLocalQueryTarget(e){return this.Lr.activeTargetIds.has(e)}clearQueryState(e){delete this.qr[e]}getAllActiveQueryTargets(){return this.Lr.activeTargetIds}isActiveQueryTarget(e){return this.Lr.activeTargetIds.has(e)}start(){return this.Lr=new lf,Promise.resolve()}handleUserChange(e,t,n){}setOnlineState(e){}shutdown(){}writeSequenceNumber(e){}notifyBundleLoaded(e){}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lg{Ur(e){}shutdown(){}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ly{constructor(){this.Kr=()=>this.Gr(),this.Qr=()=>this.jr(),this.Wr=[],this.zr()}Ur(e){this.Wr.push(e)}shutdown(){window.removeEventListener("online",this.Kr),window.removeEventListener("offline",this.Qr)}zr(){window.addEventListener("online",this.Kr),window.addEventListener("offline",this.Qr)}Gr(){for(let e of(nj("ConnectivityMonitor","Network connectivity changed: AVAILABLE"),this.Wr))e(0)}jr(){for(let e of(nj("ConnectivityMonitor","Network connectivity changed: UNAVAILABLE"),this.Wr))e(1)}static C(){return"undefined"!=typeof window&&void 0!==window.addEventListener&&void 0!==window.removeEventListener}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let lv={BatchGetDocuments:"batchGet",Commit:"commit",RunQuery:"runQuery",RunAggregationQuery:"runAggregationQuery"};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lw{constructor(e){this.Hr=e.Hr,this.Jr=e.Jr}Yr(e){this.Xr=e}Zr(e){this.eo=e}onMessage(e){this.no=e}close(){this.Jr()}send(e){this.Hr(e)}so(){this.Xr()}io(e){this.eo(e)}ro(e){this.no(e)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l_ extends class{constructor(e){this.databaseInfo=e,this.databaseId=e.databaseId;let t=e.ssl?"https":"http";this.oo=t+"://"+e.host,this.uo="projects/"+this.databaseId.projectId+"/databases/"+this.databaseId.database+"/documents"}get co(){return!1}ao(e,t,n,r,i){let s=this.ho(e,t);nj("RestConnection","Sending: ",s,n);let a={};return this.lo(a,r,i),this.fo(e,s,a,n).then(e=>(nj("RestConnection","Received: ",e),e),t=>{throw n$("RestConnection",`${e} failed with error: `,t,"url: ",s,"request:",n),t})}_o(e,t,n,r,i,s){return this.ao(e,t,n,r,i)}lo(e,t,n){e["X-Goog-Api-Client"]="gl-js/ fire/"+nF,e["Content-Type"]="text/plain",this.databaseInfo.appId&&(e["X-Firebase-GMPID"]=this.databaseInfo.appId),t&&t.headers.forEach((t,n)=>e[n]=t),n&&n.headers.forEach((t,n)=>e[n]=t)}ho(e,t){let n=lv[e];return`${this.oo}/v1/${t}:${n}`}}{constructor(e){super(e),this.forceLongPolling=e.forceLongPolling,this.autoDetectLongPolling=e.autoDetectLongPolling,this.useFetchStreams=e.useFetchStreams}fo(e,t,n,r){return new Promise((i,s)=>{let a=new nP;a.setWithCredentials(!0),a.listenOnce(nx.COMPLETE,()=>{try{switch(a.getLastErrorCode()){case nC.NO_ERROR:let t=a.getResponseJson();nj("Connection","XHR received:",JSON.stringify(t)),i(t);break;case nC.TIMEOUT:nj("Connection",'RPC "'+e+'" timed out'),s(new nQ(nH.DEADLINE_EXCEEDED,"Request time out"));break;case nC.HTTP_ERROR:let n=a.getStatus();if(nj("Connection",'RPC "'+e+'" failed with status:',n,"response text:",a.getResponseText()),n>0){let e=a.getResponseJson();Array.isArray(e)&&(e=e[0]);let t=null==e?void 0:e.error;if(t&&t.status&&t.message){let e=function(e){let t=e.toLowerCase().replace(/_/g,"-");return Object.values(nH).indexOf(t)>=0?t:nH.UNKNOWN}(t.status);s(new nQ(e,t.message))}else s(new nQ(nH.UNKNOWN,"Server responded with status "+a.getStatus()))}else s(new nQ(nH.UNAVAILABLE,"Connection failed."));break;default:nK()}}finally{nj("Connection",'RPC "'+e+'" completed.')}});let o=JSON.stringify(r);a.send(t,"POST",o,n,15)})}wo(e,t,n){let r=[this.oo,"/","google.firestore.v1.Firestore","/",e,"/channel"],i=nk(),s=nA(),a={httpSessionIdParam:"gsessionid",initMessageHeaders:{},messageUrlParams:{database:`projects/${this.databaseId.projectId}/databases/${this.databaseId.database}`},sendRawJson:!0,supportsCrossDomainXhr:!0,internalChannelParams:{forwardChannelRequestTimeoutMs:6e5},forceLongPolling:this.forceLongPolling,detectBufferingProxy:this.autoDetectLongPolling};this.useFetchStreams&&(a.xmlHttpFactory=new nD({})),this.lo(a.initMessageHeaders,t,n),a.encodeInitMessageHeaders=!0;let o=r.join("");nj("Connection","Creating WebChannel: "+o,a);let u=i.createWebChannel(o,a),c=!1,h=!1,d=new lw({Hr:e=>{h?nj("Connection","Not sending because WebChannel is closed:",e):(c||(nj("Connection","Opening WebChannel transport."),u.open(),c=!0),nj("Connection","WebChannel sending:",e),u.send(e))},Jr:()=>u.close()}),f=(e,t,n)=>{e.listen(t,e=>{try{n(e)}catch(e){setTimeout(()=>{throw e},0)}})};return f(u,nO.EventType.OPEN,()=>{h||nj("Connection","WebChannel transport opened.")}),f(u,nO.EventType.CLOSE,()=>{h||(h=!0,nj("Connection","WebChannel transport closed"),d.io())}),f(u,nO.EventType.ERROR,e=>{h||(h=!0,n$("Connection","WebChannel transport errored:",e),d.io(new nQ(nH.UNAVAILABLE,"The operation could not be completed")))}),f(u,nO.EventType.MESSAGE,e=>{var t;if(!h){let n=e.data[0];n||nK();let r=n.error||(null===(t=n[0])||void 0===t?void 0:t.error);if(r){nj("Connection","WebChannel received error:",r);let e=r.status,t=function(e){let t=l[e];if(void 0!==t)return sb(t)}(e),n=r.message;void 0===t&&(t=nH.INTERNAL,n="Unknown error status: "+e+" with message "+r.message),h=!0,d.io(new nQ(t,n)),u.close()}else nj("Connection","WebChannel received:",n),d.ro(n)}}),f(s,nN.STAT_EVENT,e=>{e.stat===nR.PROXY?nj("Connection","Detected buffering proxy"):e.stat===nR.NOPROXY&&nj("Connection","Detected no buffering proxy")}),setTimeout(()=>{d.so()},0),d}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function lb(){return"undefined"!=typeof window?window:null}function lI(){return"undefined"!=typeof document?document:null}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function lT(e){return new s$(e,!0)}class lE{constructor(e,t,n=1e3,r=1.5,i=6e4){this.Hs=e,this.timerId=t,this.mo=n,this.yo=r,this.po=i,this.Io=0,this.To=null,this.Eo=Date.now(),this.reset()}reset(){this.Io=0}Ao(){this.Io=this.po}Ro(e){this.cancel();let t=Math.floor(this.Io+this.bo()),n=Math.max(0,Date.now()-this.Eo),r=Math.max(0,t-n);r>0&&nj("ExponentialBackoff",`Backing off for ${r} ms (base delay: ${this.Io} ms, delay with jitter: ${t} ms, last attempt: ${n} ms ago)`),this.To=this.Hs.enqueueAfterDelay(this.timerId,r,()=>(this.Eo=Date.now(),e())),this.Io*=this.yo,this.Io<this.mo&&(this.Io=this.mo),this.Io>this.po&&(this.Io=this.po)}Po(){null!==this.To&&(this.To.skipDelay(),this.To=null)}cancel(){null!==this.To&&(this.To.cancel(),this.To=null)}bo(){return(Math.random()-.5)*this.Io}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lS{constructor(e,t,n,r,i,s,a,o){this.Hs=e,this.vo=n,this.Vo=r,this.connection=i,this.authCredentialsProvider=s,this.appCheckCredentialsProvider=a,this.listener=o,this.state=0,this.So=0,this.Do=null,this.Co=null,this.stream=null,this.xo=new lE(e,t)}No(){return 1===this.state||5===this.state||this.ko()}ko(){return 2===this.state||3===this.state}start(){4!==this.state?this.auth():this.Oo()}async stop(){this.No()&&await this.close(0)}Mo(){this.state=0,this.xo.reset()}Fo(){this.ko()&&null===this.Do&&(this.Do=this.Hs.enqueueAfterDelay(this.vo,6e4,()=>this.$o()))}Bo(e){this.Lo(),this.stream.send(e)}async $o(){if(this.ko())return this.close(0)}Lo(){this.Do&&(this.Do.cancel(),this.Do=null)}qo(){this.Co&&(this.Co.cancel(),this.Co=null)}async close(e,t){this.Lo(),this.qo(),this.xo.cancel(),this.So++,4!==e?this.xo.reset():t&&t.code===nH.RESOURCE_EXHAUSTED?(nz(t.toString()),nz("Using maximum backoff delay to prevent overloading the backend."),this.xo.Ao()):t&&t.code===nH.UNAUTHENTICATED&&3!==this.state&&(this.authCredentialsProvider.invalidateToken(),this.appCheckCredentialsProvider.invalidateToken()),null!==this.stream&&(this.Uo(),this.stream.close(),this.stream=null),this.state=e,await this.listener.Zr(t)}Uo(){}auth(){this.state=1;let e=this.Ko(this.So),t=this.So;Promise.all([this.authCredentialsProvider.getToken(),this.appCheckCredentialsProvider.getToken()]).then(([e,n])=>{this.So===t&&this.Go(e,n)},t=>{e(()=>{let e=new nQ(nH.UNKNOWN,"Fetching auth token failed: "+t.message);return this.Qo(e)})})}Go(e,t){let n=this.Ko(this.So);this.stream=this.jo(e,t),this.stream.Yr(()=>{n(()=>(this.state=2,this.Co=this.Hs.enqueueAfterDelay(this.Vo,1e4,()=>(this.ko()&&(this.state=3),Promise.resolve())),this.listener.Yr()))}),this.stream.Zr(e=>{n(()=>this.Qo(e))}),this.stream.onMessage(e=>{n(()=>this.onMessage(e))})}Oo(){this.state=5,this.xo.Ro(async()=>{this.state=0,this.start()})}Qo(e){return nj("PersistentStream",`close with error: ${e}`),this.stream=null,this.close(4,e)}Ko(e){return t=>{this.Hs.enqueueAndForget(()=>this.So===e?t():(nj("PersistentStream","stream callback skipped by getCloseGuardedDispatcher."),Promise.resolve()))}}}class lk extends lS{constructor(e,t,n,r,i,s){super(e,"listen_stream_connection_backoff","listen_stream_idle","health_check_timeout",t,n,r,s),this.yt=i}jo(e,t){return this.connection.wo("Listen",e,t)}onMessage(e){this.xo.reset();let t=function(e,t){let n;if("targetChange"in t){var r,i;t.targetChange;let s="NO_CHANGE"===(r=t.targetChange.targetChangeType||"NO_CHANGE")?0:"ADD"===r?1:"REMOVE"===r?2:"CURRENT"===r?3:"RESET"===r?4:nK(),a=t.targetChange.targetIds||[],o=(i=t.targetChange.resumeToken,e.wt?(void 0===i||"string"==typeof i||nK(),rV.fromBase64String(i||"")):(void 0===i||i instanceof Uint8Array||nK(),rV.fromUint8Array(i||new Uint8Array))),l=t.targetChange.cause,u=l&&function(e){let t=void 0===e.code?nH.UNKNOWN:sb(e.code);return new nQ(t,e.message||"")}(l);n=new sM(s,a,o,u||null)}else if("documentChange"in t){t.documentChange;let r=t.documentChange;r.document,r.document.name,r.document.updateTime;let i=sX(e,r.document.name),s=sW(r.document.updateTime),a=r.document.createTime?sW(r.document.createTime):n7.min(),o=new ix({mapValue:{fields:r.document.fields}}),l=iN.newFoundDocument(i,s,a,o),u=r.targetIds||[],c=r.removedTargetIds||[];n=new sP(u,c,l.key,l)}else if("documentDelete"in t){t.documentDelete;let r=t.documentDelete;r.document;let i=sX(e,r.document),s=r.readTime?sW(r.readTime):n7.min(),a=iN.newNoDocument(i,s),o=r.removedTargetIds||[];n=new sP([],o,a.key,a)}else if("documentRemove"in t){t.documentRemove;let r=t.documentRemove;r.document;let i=sX(e,r.document),s=r.removedTargetIds||[];n=new sP([],s,i,null)}else{if(!("filter"in t))return nK();{t.filter;let e=t.filter;e.targetId;let r=e.count||0,i=new sw(r),s=e.targetId;n=new sL(s,i)}}return n}(this.yt,e),n=function(e){if(!("targetChange"in e))return n7.min();let t=e.targetChange;return t.targetIds&&t.targetIds.length?n7.min():t.readTime?sW(t.readTime):n7.min()}(e);return this.listener.Wo(t,n)}zo(e){let t={};t.database=s0(this.yt),t.addTarget=function(e,t){let n;let r=t.target;return(n=iL(r)?{documents:s5(e,r)}:{query:s9(e,r)}).targetId=t.targetId,t.resumeToken.approximateByteSize()>0?n.resumeToken=sK(e,t.resumeToken):t.snapshotVersion.compareTo(n7.min())>0&&(n.readTime=sG(e,t.snapshotVersion.toTimestamp())),n}(this.yt,e);let n=function(e,t){let n=function(e,t){switch(t){case 0:return null;case 1:return"existence-filter-mismatch";case 2:return"limbo-document";default:return nK()}}(0,t.purpose);return null==n?null:{"goog-listen-tags":n}}(this.yt,e);n&&(t.labels=n),this.Bo(t)}Ho(e){let t={};t.database=s0(this.yt),t.removeTarget=e,this.Bo(t)}}class lA extends lS{constructor(e,t,n,r,i,s){super(e,"write_stream_connection_backoff","write_stream_idle","health_check_timeout",t,n,r,s),this.yt=i,this.Jo=!1}get Yo(){return this.Jo}start(){this.Jo=!1,this.lastStreamToken=void 0,super.start()}Uo(){this.Jo&&this.Xo([])}jo(e,t){return this.connection.wo("Write",e,t)}onMessage(e){var t,n;if(e.streamToken||nK(),this.lastStreamToken=e.streamToken,this.Jo){this.xo.reset();let r=(t=e.writeResults,n=e.commitTime,t&&t.length>0?(void 0!==n||nK(),t.map(e=>{let t;return(t=e.updateTime?sW(e.updateTime):sW(n)).isEqual(n7.min())&&(t=sW(n)),new ss(t,e.transformResults||[])})):[]),i=sW(e.commitTime);return this.listener.Zo(i,r)}return e.writeResults&&0!==e.writeResults.length&&nK(),this.Jo=!0,this.listener.tu()}eu(){let e={};e.database=s0(this.yt),this.Bo(e)}Xo(e){let t={streamToken:this.lastStreamToken,writes:e.map(e=>s4(this.yt,e))};this.Bo(t)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lC extends class{}{constructor(e,t,n,r){super(),this.authCredentials=e,this.appCheckCredentials=t,this.connection=n,this.yt=r,this.nu=!1}su(){if(this.nu)throw new nQ(nH.FAILED_PRECONDITION,"The client has already been terminated.")}ao(e,t,n){return this.su(),Promise.all([this.authCredentials.getToken(),this.appCheckCredentials.getToken()]).then(([r,i])=>this.connection.ao(e,t,n,r,i)).catch(e=>{throw"FirebaseError"===e.name?(e.code===nH.UNAUTHENTICATED&&(this.authCredentials.invalidateToken(),this.appCheckCredentials.invalidateToken()),e):new nQ(nH.UNKNOWN,e.toString())})}_o(e,t,n,r){return this.su(),Promise.all([this.authCredentials.getToken(),this.appCheckCredentials.getToken()]).then(([i,s])=>this.connection._o(e,t,n,i,s,r)).catch(e=>{throw"FirebaseError"===e.name?(e.code===nH.UNAUTHENTICATED&&(this.authCredentials.invalidateToken(),this.appCheckCredentials.invalidateToken()),e):new nQ(nH.UNKNOWN,e.toString())})}terminate(){this.nu=!0}}class lx{constructor(e,t){this.asyncQueue=e,this.onlineStateHandler=t,this.state="Unknown",this.iu=0,this.ru=null,this.ou=!0}uu(){0===this.iu&&(this.cu("Unknown"),this.ru=this.asyncQueue.enqueueAfterDelay("online_state_timeout",1e4,()=>(this.ru=null,this.au("Backend didn't respond within 10 seconds."),this.cu("Offline"),Promise.resolve())))}hu(e){"Online"===this.state?this.cu("Unknown"):(this.iu++,this.iu>=1&&(this.lu(),this.au(`Connection failed 1 times. Most recent error: ${e.toString()}`),this.cu("Offline")))}set(e){this.lu(),this.iu=0,"Online"===e&&(this.ou=!1),this.cu(e)}cu(e){e!==this.state&&(this.state=e,this.onlineStateHandler(e))}au(e){let t=`Could not reach Cloud Firestore backend. ${e}
This typically indicates that your device does not have a healthy Internet connection at the moment. The client will operate in offline mode until it is able to successfully connect to the backend.`;this.ou?(nz(t),this.ou=!1):nj("OnlineStateTracker",t)}lu(){null!==this.ru&&(this.ru.cancel(),this.ru=null)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lN{constructor(e,t,n,r,i){this.localStore=e,this.datastore=t,this.asyncQueue=n,this.remoteSyncer={},this.fu=[],this.du=new Map,this._u=new Set,this.wu=[],this.mu=i,this.mu.Ur(e=>{n.enqueueAndForget(async()=>{lV(this)&&(nj("RemoteStore","Restarting streams for network reachability change."),await async function(e){e._u.add(4),await lD(e),e.gu.set("Unknown"),e._u.delete(4),await lR(e)}(this))})}),this.gu=new lx(n,r)}}async function lR(e){if(lV(e))for(let t of e.wu)await t(!0)}async function lD(e){for(let t of e.wu)await t(!1)}function lO(e,t){e.du.has(t.targetId)||(e.du.set(t.targetId,t),lF(e)?lU(e):l0(e).ko()&&lL(e,t))}function lP(e,t){let n=l0(e);e.du.delete(t),n.ko()&&lM(e,t),0===e.du.size&&(n.ko()?n.Fo():lV(e)&&e.gu.set("Unknown"))}function lL(e,t){e.yu.Ot(t.targetId),l0(e).zo(t)}function lM(e,t){e.yu.Ot(t),l0(e).Ho(t)}function lU(e){e.yu=new sF({getRemoteKeysForTarget:t=>e.remoteSyncer.getRemoteKeysForTarget(t),ne:t=>e.du.get(t)||null}),l0(e).start(),e.gu.uu()}function lF(e){return lV(e)&&!l0(e).No()&&e.du.size>0}function lV(e){return 0===e._u.size}async function lq(e){e.du.forEach((t,n)=>{lL(e,t)})}async function lB(e,t){e.yu=void 0,lF(e)?(e.gu.hu(t),lU(e)):e.gu.set("Unknown")}async function lj(e,t,n){if(e.gu.set("Online"),t instanceof sM&&2===t.state&&t.cause)try{await async function(e,t){let n=t.cause;for(let r of t.targetIds)e.du.has(r)&&(await e.remoteSyncer.rejectListen(r,n),e.du.delete(r),e.yu.removeTarget(r))}(e,t)}catch(n){nj("RemoteStore","Failed to remove targets %s: %s ",t.targetIds.join(","),n),await lz(e,n)}else if(t instanceof sP?e.yu.Kt(t):t instanceof sL?e.yu.Jt(t):e.yu.jt(t),!n.isEqual(n7.min()))try{let t=await o5(e.localStore);n.compareTo(t)>=0&&await function(e,t){let n=e.yu.Zt(t);return n.targetChanges.forEach((n,r)=>{if(n.resumeToken.approximateByteSize()>0){let i=e.du.get(r);i&&e.du.set(r,i.withResumeToken(n.resumeToken,t))}}),n.targetMismatches.forEach(t=>{let n=e.du.get(t);if(!n)return;e.du.set(t,n.withResumeToken(rV.EMPTY_BYTE_STRING,n.snapshotVersion)),lM(e,t);let r=new ax(n.target,t,1,n.sequenceNumber);lL(e,r)}),e.remoteSyncer.applyRemoteEvent(n)}(e,n)}catch(t){nj("RemoteStore","Failed to raise snapshot:",t),await lz(e,t)}}async function lz(e,t,n){if(!rI(t))throw t;e._u.add(1),await lD(e),e.gu.set("Offline"),n||(n=()=>o5(e.localStore)),e.asyncQueue.enqueueRetryable(async()=>{nj("RemoteStore","Retrying IndexedDB access"),await n(),e._u.delete(1),await lR(e)})}function l$(e,t){return t().catch(n=>lz(e,n,t))}async function lG(e){let t=l1(e),n=e.fu.length>0?e.fu[e.fu.length-1].batchId:-1;for(;lV(e)&&e.fu.length<10;)try{let r=await function(e,t){return e.persistence.runTransaction("Get next mutation batch","readonly",n=>(void 0===t&&(t=-1),e.mutationQueue.getNextMutationBatchAfterBatchId(n,t)))}(e.localStore,n);if(null===r){0===e.fu.length&&t.Fo();break}n=r.batchId,function(e,t){e.fu.push(t);let n=l1(e);n.ko()&&n.Yo&&n.Xo(t.mutations)}(e,r)}catch(t){await lz(e,t)}lK(e)&&lW(e)}function lK(e){return lV(e)&&!l1(e).No()&&e.fu.length>0}function lW(e){l1(e).start()}async function lH(e){l1(e).eu()}async function lQ(e){let t=l1(e);for(let n of e.fu)t.Xo(n.mutations)}async function lY(e,t,n){let r=e.fu.shift(),i=aA.from(r,t,n);await l$(e,()=>e.remoteSyncer.applySuccessfulWrite(i)),await lG(e)}async function lX(e,t){t&&l1(e).Yo&&await async function(e,t){var n;if(s_(n=t.code)&&n!==nH.ABORTED){let n=e.fu.shift();l1(e).Mo(),await l$(e,()=>e.remoteSyncer.rejectFailedWrite(n.batchId,t)),await lG(e)}}(e,t),lK(e)&&lW(e)}async function lJ(e,t){e.asyncQueue.verifyOperationInProgress(),nj("RemoteStore","RemoteStore received new credentials");let n=lV(e);e._u.add(3),await lD(e),n&&e.gu.set("Unknown"),await e.remoteSyncer.handleCredentialChange(t),e._u.delete(3),await lR(e)}async function lZ(e,t){t?(e._u.delete(2),await lR(e)):t||(e._u.add(2),await lD(e),e.gu.set("Unknown"))}function l0(e){var t,n,r;return e.pu||(e.pu=(t=e.datastore,n=e.asyncQueue,r={Yr:lq.bind(null,e),Zr:lB.bind(null,e),Wo:lj.bind(null,e)},t.su(),new lk(n,t.connection,t.authCredentials,t.appCheckCredentials,t.yt,r)),e.wu.push(async t=>{t?(e.pu.Mo(),lF(e)?lU(e):e.gu.set("Unknown")):(await e.pu.stop(),e.yu=void 0)})),e.pu}function l1(e){var t,n,r;return e.Iu||(e.Iu=(t=e.datastore,n=e.asyncQueue,r={Yr:lH.bind(null,e),Zr:lX.bind(null,e),tu:lQ.bind(null,e),Zo:lY.bind(null,e)},t.su(),new lA(n,t.connection,t.authCredentials,t.appCheckCredentials,t.yt,r)),e.wu.push(async t=>{t?(e.Iu.Mo(),await lG(e)):(await e.Iu.stop(),e.fu.length>0&&(nj("RemoteStore",`Stopping write stream with ${e.fu.length} pending writes`),e.fu=[]))})),e.Iu}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l2{constructor(e,t,n,r,i){this.asyncQueue=e,this.timerId=t,this.targetTimeMs=n,this.op=r,this.removalCallback=i,this.deferred=new nY,this.then=this.deferred.promise.then.bind(this.deferred.promise),this.deferred.promise.catch(e=>{})}static createAndSchedule(e,t,n,r,i){let s=Date.now()+n,a=new l2(e,t,s,r,i);return a.start(n),a}start(e){this.timerHandle=setTimeout(()=>this.handleDelayElapsed(),e)}skipDelay(){return this.handleDelayElapsed()}cancel(e){null!==this.timerHandle&&(this.clearTimeout(),this.deferred.reject(new nQ(nH.CANCELLED,"Operation cancelled"+(e?": "+e:""))))}handleDelayElapsed(){this.asyncQueue.enqueueAndForget(()=>null!==this.timerHandle?(this.clearTimeout(),this.op().then(e=>this.deferred.resolve(e))):Promise.resolve())}clearTimeout(){null!==this.timerHandle&&(this.removalCallback(this),clearTimeout(this.timerHandle),this.timerHandle=null)}}function l3(e,t){if(nz("AsyncQueue",`${t}: ${e}`),rI(e))return new nQ(nH.UNAVAILABLE,`${t}: ${e}`);throw e}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l4{constructor(e){this.comparator=e?(t,n)=>e(t,n)||ri.comparator(t.key,n.key):(e,t)=>ri.comparator(e.key,t.key),this.keyedMap=sS(),this.sortedSet=new iI(this.comparator)}static emptySet(e){return new l4(e.comparator)}has(e){return null!=this.keyedMap.get(e)}get(e){return this.keyedMap.get(e)}first(){return this.sortedSet.minKey()}last(){return this.sortedSet.maxKey()}isEmpty(){return this.sortedSet.isEmpty()}indexOf(e){let t=this.keyedMap.get(e);return t?this.sortedSet.indexOf(t):-1}get size(){return this.sortedSet.size}forEach(e){this.sortedSet.inorderTraversal((t,n)=>(e(t),!1))}add(e){let t=this.delete(e.key);return t.copy(t.keyedMap.insert(e.key,e),t.sortedSet.insert(e,null))}delete(e){let t=this.get(e);return t?this.copy(this.keyedMap.remove(e),this.sortedSet.remove(t)):this}isEqual(e){if(!(e instanceof l4)||this.size!==e.size)return!1;let t=this.sortedSet.getIterator(),n=e.sortedSet.getIterator();for(;t.hasNext();){let e=t.getNext().key,r=n.getNext().key;if(!e.isEqual(r))return!1}return!0}toString(){let e=[];return this.forEach(t=>{e.push(t.toString())}),0===e.length?"DocumentSet ()":"DocumentSet (\n  "+e.join("  \n")+"\n)"}copy(e,t){let n=new l4;return n.comparator=this.comparator,n.keyedMap=e,n.sortedSet=t,n}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l6{constructor(){this.Tu=new iI(ri.comparator)}track(e){let t=e.doc.key,n=this.Tu.get(t);n?0!==e.type&&3===n.type?this.Tu=this.Tu.insert(t,e):3===e.type&&1!==n.type?this.Tu=this.Tu.insert(t,{type:n.type,doc:e.doc}):2===e.type&&2===n.type?this.Tu=this.Tu.insert(t,{type:2,doc:e.doc}):2===e.type&&0===n.type?this.Tu=this.Tu.insert(t,{type:0,doc:e.doc}):1===e.type&&0===n.type?this.Tu=this.Tu.remove(t):1===e.type&&2===n.type?this.Tu=this.Tu.insert(t,{type:1,doc:n.doc}):0===e.type&&1===n.type?this.Tu=this.Tu.insert(t,{type:2,doc:e.doc}):nK():this.Tu=this.Tu.insert(t,e)}Eu(){let e=[];return this.Tu.inorderTraversal((t,n)=>{e.push(n)}),e}}class l5{constructor(e,t,n,r,i,s,a,o,l){this.query=e,this.docs=t,this.oldDocs=n,this.docChanges=r,this.mutatedKeys=i,this.fromCache=s,this.syncStateChanged=a,this.excludesMetadataChanges=o,this.hasCachedResults=l}static fromInitialDocuments(e,t,n,r,i){let s=[];return t.forEach(e=>{s.push({type:0,doc:e})}),new l5(e,t,l4.emptySet(t),s,n,r,!0,!1,i)}get hasPendingWrites(){return!this.mutatedKeys.isEmpty()}isEqual(e){if(!(this.fromCache===e.fromCache&&this.hasCachedResults===e.hasCachedResults&&this.syncStateChanged===e.syncStateChanged&&this.mutatedKeys.isEqual(e.mutatedKeys)&&iQ(this.query,e.query)&&this.docs.isEqual(e.docs)&&this.oldDocs.isEqual(e.oldDocs)))return!1;let t=this.docChanges,n=e.docChanges;if(t.length!==n.length)return!1;for(let e=0;e<t.length;e++)if(t[e].type!==n[e].type||!t[e].doc.isEqual(n[e].doc))return!1;return!0}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l9{constructor(){this.Au=void 0,this.listeners=[]}}class l8{constructor(){this.queries=new sI(e=>iY(e),iQ),this.onlineState="Unknown",this.Ru=new Set}}async function l7(e,t){let n=t.query,r=!1,i=e.queries.get(n);if(i||(r=!0,i=new l9),r)try{i.Au=await e.onListen(n)}catch(n){let e=l3(n,`Initialization of query '${iX(t.query)}' failed`);return void t.onError(e)}e.queries.set(n,i),i.listeners.push(t),t.bu(e.onlineState),i.Au&&t.Pu(i.Au)&&ur(e)}async function ue(e,t){let n=t.query,r=!1,i=e.queries.get(n);if(i){let e=i.listeners.indexOf(t);e>=0&&(i.listeners.splice(e,1),r=0===i.listeners.length)}if(r)return e.queries.delete(n),e.onUnlisten(n)}function ut(e,t){let n=!1;for(let r of t){let t=r.query,i=e.queries.get(t);if(i){for(let e of i.listeners)e.Pu(r)&&(n=!0);i.Au=r}}n&&ur(e)}function un(e,t,n){let r=e.queries.get(t);if(r)for(let e of r.listeners)e.onError(n);e.queries.delete(t)}function ur(e){e.Ru.forEach(e=>{e.next()})}class ui{constructor(e,t,n){this.query=e,this.vu=t,this.Vu=!1,this.Su=null,this.onlineState="Unknown",this.options=n||{}}Pu(e){if(!this.options.includeMetadataChanges){let t=[];for(let n of e.docChanges)3!==n.type&&t.push(n);e=new l5(e.query,e.docs,e.oldDocs,t,e.mutatedKeys,e.fromCache,e.syncStateChanged,!0,e.hasCachedResults)}let t=!1;return this.Vu?this.Du(e)&&(this.vu.next(e),t=!0):this.Cu(e,this.onlineState)&&(this.xu(e),t=!0),this.Su=e,t}onError(e){this.vu.error(e)}bu(e){this.onlineState=e;let t=!1;return this.Su&&!this.Vu&&this.Cu(this.Su,e)&&(this.xu(this.Su),t=!0),t}Cu(e,t){return!e.fromCache||(!this.options.Nu||!("Offline"!==t))&&(!e.docs.isEmpty()||e.hasCachedResults||"Offline"===t)}Du(e){if(e.docChanges.length>0)return!0;let t=this.Su&&this.Su.hasPendingWrites!==e.hasPendingWrites;return!(!e.syncStateChanged&&!t)&&!0===this.options.includeMetadataChanges}xu(e){e=l5.fromInitialDocuments(e.query,e.docs,e.mutatedKeys,e.fromCache,e.hasCachedResults),this.Vu=!0,this.vu.next(e)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class us{constructor(e,t){this.ku=e,this.byteLength=t}Ou(){return"metadata"in this.ku}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ua{constructor(e){this.yt=e}Ji(e){return sX(this.yt,e)}Yi(e){return e.metadata.exists?s3(this.yt,e.document,!1):iN.newNoDocument(this.Ji(e.metadata.name),this.Xi(e.metadata.readTime))}Xi(e){return sW(e)}}class uo{constructor(e,t,n){this.Mu=e,this.localStore=t,this.yt=n,this.queries=[],this.documents=[],this.collectionGroups=new Set,this.progress=ul(e)}Fu(e){this.progress.bytesLoaded+=e.byteLength;let t=this.progress.documentsLoaded;if(e.ku.namedQuery)this.queries.push(e.ku.namedQuery);else if(e.ku.documentMetadata){this.documents.push({metadata:e.ku.documentMetadata}),e.ku.documentMetadata.exists||++t;let n=rt.fromString(e.ku.documentMetadata.name);this.collectionGroups.add(n.get(n.length-2))}else e.ku.document&&(this.documents[this.documents.length-1].document=e.ku.document,++t);return t!==this.progress.documentsLoaded?(this.progress.documentsLoaded=t,Object.assign({},this.progress)):null}$u(e){let t=new Map,n=new ua(this.yt);for(let r of e)if(r.metadata.queries){let e=n.Ji(r.metadata.name);for(let n of r.metadata.queries){let r=(t.get(n)||sN()).add(e);t.set(n,r)}}return t}async complete(){let e=await li(this.localStore,new ua(this.yt),this.documents,this.Mu.id),t=this.$u(this.documents);for(let e of this.queries)await ls(this.localStore,e,t.get(e.name));return this.progress.taskState="Success",{progress:this.progress,Bu:this.collectionGroups,Lu:e}}}function ul(e){return{taskState:"Running",documentsLoaded:0,bytesLoaded:0,totalDocuments:e.totalDocuments,totalBytes:e.totalBytes}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class uu{constructor(e){this.key=e}}class uc{constructor(e){this.key=e}}class uh{constructor(e,t){this.query=e,this.qu=t,this.Uu=null,this.hasCachedResults=!1,this.current=!1,this.Ku=sN(),this.mutatedKeys=sN(),this.Gu=i0(e),this.Qu=new l4(this.Gu)}get ju(){return this.qu}Wu(e,t){let n=t?t.zu:new l6,r=t?t.Qu:this.Qu,i=t?t.mutatedKeys:this.mutatedKeys,s=r,a=!1,o="F"===this.query.limitType&&r.size===this.query.limit?r.last():null,l="L"===this.query.limitType&&r.size===this.query.limit?r.first():null;if(e.inorderTraversal((e,t)=>{let u=r.get(e),c=iJ(this.query,t)?t:null,h=!!u&&this.mutatedKeys.has(u.key),d=!!c&&(c.hasLocalMutations||this.mutatedKeys.has(c.key)&&c.hasCommittedMutations),f=!1;u&&c?u.data.isEqual(c.data)?h!==d&&(n.track({type:3,doc:c}),f=!0):this.Hu(u,c)||(n.track({type:2,doc:c}),f=!0,(o&&this.Gu(c,o)>0||l&&0>this.Gu(c,l))&&(a=!0)):!u&&c?(n.track({type:0,doc:c}),f=!0):u&&!c&&(n.track({type:1,doc:u}),f=!0,(o||l)&&(a=!0)),f&&(c?(s=s.add(c),i=d?i.add(e):i.delete(e)):(s=s.delete(e),i=i.delete(e)))}),null!==this.query.limit)for(;s.size>this.query.limit;){let e="F"===this.query.limitType?s.last():s.first();s=s.delete(e.key),i=i.delete(e.key),n.track({type:1,doc:e})}return{Qu:s,zu:n,$i:a,mutatedKeys:i}}Hu(e,t){return e.hasLocalMutations&&t.hasCommittedMutations&&!t.hasLocalMutations}applyChanges(e,t,n){let r=this.Qu;this.Qu=e.Qu,this.mutatedKeys=e.mutatedKeys;let i=e.zu.Eu();i.sort((e,t)=>(function(e,t){let n=e=>{switch(e){case 0:return 1;case 2:case 3:return 2;case 1:return 0;default:return nK()}};return n(e)-n(t)})(e.type,t.type)||this.Gu(e.doc,t.doc)),this.Ju(n);let s=t?this.Yu():[],a=0===this.Ku.size&&this.current?1:0,o=a!==this.Uu;return(this.Uu=a,0!==i.length||o)?{snapshot:new l5(this.query,e.Qu,r,i,e.mutatedKeys,0===a,o,!1,!!n&&n.resumeToken.approximateByteSize()>0),Xu:s}:{Xu:s}}bu(e){return this.current&&"Offline"===e?(this.current=!1,this.applyChanges({Qu:this.Qu,zu:new l6,mutatedKeys:this.mutatedKeys,$i:!1},!1)):{Xu:[]}}Zu(e){return!this.qu.has(e)&&!!this.Qu.has(e)&&!this.Qu.get(e).hasLocalMutations}Ju(e){e&&(e.addedDocuments.forEach(e=>this.qu=this.qu.add(e)),e.modifiedDocuments.forEach(e=>{}),e.removedDocuments.forEach(e=>this.qu=this.qu.delete(e)),this.current=e.current)}Yu(){if(!this.current)return[];let e=this.Ku;this.Ku=sN(),this.Qu.forEach(e=>{this.Zu(e.key)&&(this.Ku=this.Ku.add(e.key))});let t=[];return e.forEach(e=>{this.Ku.has(e)||t.push(new uc(e))}),this.Ku.forEach(n=>{e.has(n)||t.push(new uu(n))}),t}tc(e){this.qu=e.Hi,this.Ku=sN();let t=this.Wu(e.documents);return this.applyChanges(t,!0)}ec(){return l5.fromInitialDocuments(this.query,this.Qu,this.mutatedKeys,0===this.Uu,this.hasCachedResults)}}class ud{constructor(e,t,n){this.query=e,this.targetId=t,this.view=n}}class uf{constructor(e){this.key=e,this.nc=!1}}class up{constructor(e,t,n,r,i,s){this.localStore=e,this.remoteStore=t,this.eventManager=n,this.sharedClientState=r,this.currentUser=i,this.maxConcurrentLimboResolutions=s,this.sc={},this.ic=new sI(e=>iY(e),iQ),this.rc=new Map,this.oc=new Set,this.uc=new iI(ri.comparator),this.cc=new Map,this.ac=new oq,this.hc={},this.lc=new Map,this.fc=oy.vn(),this.onlineState="Unknown",this.dc=void 0}get isPrimaryClient(){return!0===this.dc}}async function um(e,t){let n,r;let i=uz(e),s=i.ic.get(t);if(s)n=s.targetId,i.sharedClientState.addLocalQueryTarget(n),r=s.view.ec();else{let e=await o8(i.localStore,iK(t));i.isPrimaryClient&&lO(i.remoteStore,e);let s=i.sharedClientState.addLocalQueryTarget(e.targetId);r=await ug(i,t,n=e.targetId,"current"===s,e.resumeToken)}return r}async function ug(e,t,n,r,i){e._c=(t,n,r)=>(async function(e,t,n,r){let i=t.view.Wu(n);i.$i&&(i=await le(e.localStore,t.query,!1).then(({documents:e})=>t.view.Wu(e,i)));let s=r&&r.targetChanges.get(t.targetId),a=t.view.applyChanges(i,e.isPrimaryClient,s);return ux(e,t.targetId,a.Xu),a.snapshot})(e,t,n,r);let s=await le(e.localStore,t,!0),a=new uh(t,s.Hi),o=a.Wu(s.documents),l=sO.createSynthesizedTargetChangeForCurrentChange(n,r&&"Offline"!==e.onlineState,i),u=a.applyChanges(o,e.isPrimaryClient,l);ux(e,n,u.Xu);let c=new ud(t,n,a);return e.ic.set(t,c),e.rc.has(n)?e.rc.get(n).push(t):e.rc.set(n,[t]),u.snapshot}async function uy(e,t){let n=e.ic.get(t),r=e.rc.get(n.targetId);if(r.length>1)return e.rc.set(n.targetId,r.filter(e=>!iQ(e,t))),void e.ic.delete(t);e.isPrimaryClient?(e.sharedClientState.removeLocalQueryTarget(n.targetId),e.sharedClientState.isActiveQueryTarget(n.targetId)||await o7(e.localStore,n.targetId,!1).then(()=>{e.sharedClientState.clearQueryState(n.targetId),lP(e.remoteStore,n.targetId),uA(e,n.targetId)}).catch(rg)):(uA(e,n.targetId),await o7(e.localStore,n.targetId,!0))}async function uv(e,t,n){let r=u$(e);try{var i,s;let e;let a=await function(e,t){let n,r;let i=n8.now(),s=t.reduce((e,t)=>e.add(t.key),sN());return e.persistence.runTransaction("Locally write mutations","readwrite",a=>{let o=sT,l=sN();return e.Gi.getEntries(a,s).next(e=>{(o=e).forEach((e,t)=>{t.isValidDocument()||(l=l.add(e))})}).next(()=>e.localDocuments.getOverlayedDocuments(a,o)).next(r=>{n=r;let s=[];for(let e of t){let t=function(e,t){let n=null;for(let r of e.fieldTransforms){let e=t.data.field(r.field),i=i6(r.transform,e||null);null!=i&&(null===n&&(n=ix.empty()),n.set(r.field,i))}return n||null}(e,n.get(e.key).overlayedDocument);null!=t&&s.push(new sf(e.key,t,function e(t){let n=[];return rO(t.fields,(t,r)=>{let i=new rr([t]);if(r6(r)){let t=e(r.mapValue).fields;if(0===t.length)n.push(i);else for(let e of t)n.push(i.child(e))}else n.push(i)}),new iC(n)}(t.value.mapValue),sa.exists(!0)))}return e.mutationQueue.addMutationBatch(a,i,s,t)}).next(t=>{r=t;let i=t.applyToLocalDocumentSet(n,l);return e.documentOverlayCache.saveOverlays(a,t.batchId,i)})}).then(()=>({batchId:r.batchId,changes:sk(n)}))}(r.localStore,t);r.sharedClientState.addPendingMutation(a.batchId),i=r,s=a.batchId,(e=i.hc[i.currentUser.toKey()])||(e=new iI(n5)),e=e.insert(s,n),i.hc[i.currentUser.toKey()]=e,await uR(r,a.changes),await lG(r.remoteStore)}catch(t){let e=l3(t,"Failed to persist write");n.reject(e)}}async function uw(e,t){try{let n=await function(e,t){let n=e,r=t.snapshotVersion,i=n.qi;return n.persistence.runTransaction("Apply remote event","readwrite-primary",e=>{let s=n.Gi.newChangeBuffer({trackRemovals:!0});i=n.qi;let a=[];t.targetChanges.forEach((s,o)=>{var l;let u=i.get(o);if(!u)return;a.push(n.Cs.removeMatchingKeys(e,s.removedDocuments,o).next(()=>n.Cs.addMatchingKeys(e,s.addedDocuments,o)));let c=u.withSequenceNumber(e.currentSequenceNumber);t.targetMismatches.has(o)?c=c.withResumeToken(rV.EMPTY_BYTE_STRING,n7.min()).withLastLimboFreeSnapshotVersion(n7.min()):s.resumeToken.approximateByteSize()>0&&(c=c.withResumeToken(s.resumeToken,r)),i=i.insert(o,c),l=c,(0===u.resumeToken.approximateByteSize()||l.snapshotVersion.toMicroseconds()-u.snapshotVersion.toMicroseconds()>=3e8||s.addedDocuments.size+s.modifiedDocuments.size+s.removedDocuments.size>0)&&a.push(n.Cs.updateTargetData(e,c))});let o=sT,l=sN();if(t.documentUpdates.forEach(r=>{t.resolvedLimboDocuments.has(r)&&a.push(n.persistence.referenceDelegate.updateLimboDocument(e,r))}),a.push(o9(e,s,t.documentUpdates).next(e=>{o=e.Wi,l=e.zi})),!r.isEqual(n7.min())){let t=n.Cs.getLastRemoteSnapshotVersion(e).next(t=>n.Cs.setTargetsMetadata(e,e.currentSequenceNumber,r));a.push(t)}return ry.waitFor(a).next(()=>s.apply(e)).next(()=>n.localDocuments.getLocalViewOfDocuments(e,o,l)).next(()=>o)}).then(e=>(n.qi=i,e))}(e.localStore,t);t.targetChanges.forEach((t,n)=>{let r=e.cc.get(n);r&&(t.addedDocuments.size+t.modifiedDocuments.size+t.removedDocuments.size<=1||nK(),t.addedDocuments.size>0?r.nc=!0:t.modifiedDocuments.size>0?r.nc||nK():t.removedDocuments.size>0&&(r.nc||nK(),r.nc=!1))}),await uR(e,n,t)}catch(e){await rg(e)}}function u_(e,t,n){let r=e;if(r.isPrimaryClient&&0===n||!r.isPrimaryClient&&1===n){let e=[];r.ic.forEach((n,r)=>{let i=r.view.bu(t);i.snapshot&&e.push(i.snapshot)}),function(e,t){let n=e;n.onlineState=t;let r=!1;n.queries.forEach((e,n)=>{for(let e of n.listeners)e.bu(t)&&(r=!0)}),r&&ur(n)}(r.eventManager,t),e.length&&r.sc.Wo(e),r.onlineState=t,r.isPrimaryClient&&r.sharedClientState.setOnlineState(t)}}async function ub(e,t,n){let r=e;r.sharedClientState.updateQueryState(t,"rejected",n);let i=r.cc.get(t),s=i&&i.key;if(s){let e=new iI(ri.comparator);e=e.insert(s,iN.newNoDocument(s,n7.min()));let n=sN().add(s),i=new sD(n7.min(),new Map,new iS(n5),e,n);await uw(r,i),r.uc=r.uc.remove(s),r.cc.delete(t),uN(r)}else await o7(r.localStore,t,!1).then(()=>uA(r,t,n)).catch(rg)}async function uI(e,t){var n;let r=t.batch.batchId;try{let i=await (n=e.localStore).persistence.runTransaction("Acknowledge batch","readwrite-primary",e=>{let r=t.batch.keys(),i=n.Gi.newChangeBuffer({trackRemovals:!0});return(function(e,t,n,r){let i=n.batch,s=i.keys(),a=ry.resolve();return s.forEach(e=>{a=a.next(()=>r.getEntry(t,e)).next(t=>{let s=n.docVersions.get(e);null!==s||nK(),0>t.version.compareTo(s)&&(i.applyToRemoteDocument(t,n),t.isValidDocument()&&(t.setReadTime(n.commitVersion),r.addEntry(t)))})}),a.next(()=>e.mutationQueue.removeMutationBatch(t,i))})(n,e,t,i).next(()=>i.apply(e)).next(()=>n.mutationQueue.performConsistencyCheck(e)).next(()=>n.documentOverlayCache.removeOverlaysForBatchId(e,r,t.batch.batchId)).next(()=>n.localDocuments.recalculateAndSaveOverlaysForDocumentKeys(e,function(e){let t=sN();for(let n=0;n<e.mutationResults.length;++n)e.mutationResults[n].transformResults.length>0&&(t=t.add(e.batch.mutations[n].key));return t}(t))).next(()=>n.localDocuments.getDocuments(e,r))});uk(e,r,null),uS(e,r),e.sharedClientState.updateMutationState(r,"acknowledged"),await uR(e,i)}catch(e){await rg(e)}}async function uT(e,t,n){var r;try{let i=await (r=e.localStore).persistence.runTransaction("Reject batch","readwrite-primary",e=>{let n;return r.mutationQueue.lookupMutationBatch(e,t).next(t=>(null!==t||nK(),n=t.keys(),r.mutationQueue.removeMutationBatch(e,t))).next(()=>r.mutationQueue.performConsistencyCheck(e)).next(()=>r.documentOverlayCache.removeOverlaysForBatchId(e,n,t)).next(()=>r.localDocuments.recalculateAndSaveOverlaysForDocumentKeys(e,n)).next(()=>r.localDocuments.getDocuments(e,n))});uk(e,t,n),uS(e,t),e.sharedClientState.updateMutationState(t,"rejected",n),await uR(e,i)}catch(e){await rg(e)}}async function uE(e,t){var n;lV(e.remoteStore)||nj("SyncEngine","The network is disabled. The task returned by 'awaitPendingWrites()' will not complete until the network is enabled.");try{let r=await (n=e.localStore).persistence.runTransaction("Get highest unacknowledged batch id","readonly",e=>n.mutationQueue.getHighestUnacknowledgedBatchId(e));if(-1===r)return void t.resolve();let i=e.lc.get(r)||[];i.push(t),e.lc.set(r,i)}catch(n){let e=l3(n,"Initialization of waitForPendingWrites() operation failed");t.reject(e)}}function uS(e,t){(e.lc.get(t)||[]).forEach(e=>{e.resolve()}),e.lc.delete(t)}function uk(e,t,n){let r=e,i=r.hc[r.currentUser.toKey()];if(i){let e=i.get(t);e&&(n?e.reject(n):e.resolve(),i=i.remove(t)),r.hc[r.currentUser.toKey()]=i}}function uA(e,t,n=null){for(let r of(e.sharedClientState.removeLocalQueryTarget(t),e.rc.get(t)))e.ic.delete(r),n&&e.sc.wc(r,n);e.rc.delete(t),e.isPrimaryClient&&e.ac.ls(t).forEach(t=>{e.ac.containsKey(t)||uC(e,t)})}function uC(e,t){e.oc.delete(t.path.canonicalString());let n=e.uc.get(t);null!==n&&(lP(e.remoteStore,n),e.uc=e.uc.remove(t),e.cc.delete(n),uN(e))}function ux(e,t,n){for(let r of n)r instanceof uu?(e.ac.addReference(r.key,t),function(e,t){let n=t.key,r=n.path.canonicalString();e.uc.get(n)||e.oc.has(r)||(nj("SyncEngine","New document in limbo: "+n),e.oc.add(r),uN(e))}(e,r)):r instanceof uc?(nj("SyncEngine","Document no longer in limbo: "+r.key),e.ac.removeReference(r.key,t),e.ac.containsKey(r.key)||uC(e,r.key)):nK()}function uN(e){for(;e.oc.size>0&&e.uc.size<e.maxConcurrentLimboResolutions;){let t=e.oc.values().next().value;e.oc.delete(t);let n=new ri(rt.fromString(t)),r=e.fc.next();e.cc.set(r,new uf(n)),e.uc=e.uc.insert(n,r),lO(e.remoteStore,new ax(iK(iq(n.path)),r,2,rx.at))}}async function uR(e,t,n){let r=[],i=[],s=[];e.ic.isEmpty()||(e.ic.forEach((a,o)=>{s.push(e._c(o,t,n).then(t=>{if((t||n)&&e.isPrimaryClient&&e.sharedClientState.updateQueryState(o.targetId,(null==t?void 0:t.fromCache)?"not-current":"current"),t){r.push(t);let e=o2.Ci(o.targetId,t);i.push(e)}}))}),await Promise.all(s),e.sc.Wo(r),await async function(e,t){let n=e;try{await n.persistence.runTransaction("notifyLocalViewChanges","readwrite",e=>ry.forEach(t,t=>ry.forEach(t.Si,r=>n.persistence.referenceDelegate.addReference(e,t.targetId,r)).next(()=>ry.forEach(t.Di,r=>n.persistence.referenceDelegate.removeReference(e,t.targetId,r)))))}catch(e){if(!rI(e))throw e;nj("LocalStore","Failed to update sequence numbers: "+e)}for(let e of t){let t=e.targetId;if(!e.fromCache){let e=n.qi.get(t),r=e.snapshotVersion,i=e.withLastLimboFreeSnapshotVersion(r);n.qi=n.qi.insert(t,i)}}}(e.localStore,i))}async function uD(e,t){let n=e;if(!n.currentUser.isEqual(t)){nj("SyncEngine","User change. New user:",t.toKey());let e=await o6(n.localStore,t);n.currentUser=t,n.lc.forEach(e=>{e.forEach(e=>{e.reject(new nQ(nH.CANCELLED,"'waitForPendingWrites' promise is rejected due to a user change."))})}),n.lc.clear(),n.sharedClientState.handleUserChange(t,e.removedBatchIds,e.addedBatchIds),await uR(n,e.ji)}}function uO(e,t){let n=e.cc.get(t);if(n&&n.nc)return sN().add(n.key);{let n=sN(),r=e.rc.get(t);if(!r)return n;for(let t of r){let r=e.ic.get(t);n=n.unionWith(r.view.ju)}return n}}async function uP(e,t){let n=await le(e.localStore,t.query,!0),r=t.view.tc(n);return e.isPrimaryClient&&ux(e,t.targetId,r.Xu),r}async function uL(e,t){return ln(e.localStore,t).then(t=>uR(e,t))}async function uM(e,t,n,r){let i=await function(e,t){let n=e.mutationQueue;return e.persistence.runTransaction("Lookup mutation documents","readonly",r=>n.Tn(r,t).next(t=>t?e.localDocuments.getDocuments(r,t):ry.resolve(null)))}(e.localStore,t);null!==i?("pending"===n?await lG(e.remoteStore):"acknowledged"===n||"rejected"===n?(uk(e,t,r||null),uS(e,t),function(e,t){e.mutationQueue.An(t)}(e.localStore,t)):nK(),await uR(e,i)):nj("SyncEngine","Cannot apply mutation batch with id: "+t)}async function uU(e,t){let n=e;if(uz(n),u$(n),!0===t&&!0!==n.dc){let e=n.sharedClientState.getAllActiveQueryTargets(),t=await uF(n,e.toArray());for(let e of(n.dc=!0,await lZ(n.remoteStore,!0),t))lO(n.remoteStore,e)}else if(!1===t&&!1!==n.dc){let e=[],t=Promise.resolve();n.rc.forEach((r,i)=>{n.sharedClientState.isLocalQueryTarget(i)?e.push(i):t=t.then(()=>(uA(n,i),o7(n.localStore,i,!0))),lP(n.remoteStore,i)}),await t,await uF(n,e),function(e){let t=e;t.cc.forEach((e,n)=>{lP(t.remoteStore,n)}),t.ac.fs(),t.cc=new Map,t.uc=new iI(ri.comparator)}(n),n.dc=!1,await lZ(n.remoteStore,!1)}}async function uF(e,t,n){let r=[],i=[];for(let n of t){let t;let s=e.rc.get(n);if(s&&0!==s.length)for(let n of(t=await o8(e.localStore,iK(s[0])),s)){let t=e.ic.get(n),r=await uP(e,t);r.snapshot&&i.push(r.snapshot)}else{let r=await lt(e.localStore,n);await ug(e,uV(r),n,!1,(t=await o8(e.localStore,r)).resumeToken)}r.push(t)}return e.sc.Wo(i),r}function uV(e){var t,n,r,i,s,a,o;return t=e.path,n=e.collectionGroup,r=e.orderBy,i=e.filters,s=e.limit,a=e.startAt,o=e.endAt,new iV(t,n,r,i,s,"F",a,o)}function uq(e){return e.localStore.persistence.vi()}async function uB(e,t,n,r){if(e.dc)return void nj("SyncEngine","Ignoring unexpected query state notification.");let i=e.rc.get(t);if(i&&i.length>0)switch(n){case"current":case"not-current":{let r=await ln(e.localStore,iZ(i[0])),s=sD.createSynthesizedRemoteEventForCurrentChange(t,"current"===n,rV.EMPTY_BYTE_STRING);await uR(e,r,s);break}case"rejected":await o7(e.localStore,t,!0),uA(e,t,r);break;default:nK()}}async function uj(e,t,n){let r=uz(e);if(r.dc){for(let e of t){if(r.rc.has(e)){nj("SyncEngine","Adding an already active target "+e);continue}let t=await lt(r.localStore,e),n=await o8(r.localStore,t);await ug(r,uV(t),n.targetId,!1,n.resumeToken),lO(r.remoteStore,n)}for(let e of n)r.rc.has(e)&&await o7(r.localStore,e,!1).then(()=>{lP(r.remoteStore,e),uA(r,e)}).catch(rg)}}function uz(e){let t=e;return t.remoteStore.remoteSyncer.applyRemoteEvent=uw.bind(null,t),t.remoteStore.remoteSyncer.getRemoteKeysForTarget=uO.bind(null,t),t.remoteStore.remoteSyncer.rejectListen=ub.bind(null,t),t.sc.Wo=ut.bind(null,t.eventManager),t.sc.wc=un.bind(null,t.eventManager),t}function u$(e){let t=e;return t.remoteStore.remoteSyncer.applySuccessfulWrite=uI.bind(null,t),t.remoteStore.remoteSyncer.rejectFailedWrite=uT.bind(null,t),t}class uG{constructor(){this.synchronizeTabs=!1}async initialize(e){this.yt=lT(e.databaseInfo.databaseId),this.sharedClientState=this.gc(e),this.persistence=this.yc(e),await this.persistence.start(),this.localStore=this.Ic(e),this.gcScheduler=this.Tc(e,this.localStore),this.indexBackfillerScheduler=this.Ec(e,this.localStore)}Tc(e,t){return null}Ec(e,t){return null}Ic(e){var t,n,r,i;return t=this.persistence,n=new o3,r=e.initialUser,i=this.yt,new o4(t,n,r,i)}yc(e){return new oK(oH.Bs,this.yt)}gc(e){return new lm}async terminate(){this.gcScheduler&&this.gcScheduler.stop(),await this.sharedClientState.shutdown(),await this.persistence.shutdown()}}class uK extends uG{constructor(e,t,n){super(),this.Ac=e,this.cacheSizeBytes=t,this.forceOwnership=n,this.synchronizeTabs=!1}async initialize(e){await super.initialize(e),await this.Ac.initialize(this,e),await u$(this.Ac.syncEngine),await lG(this.Ac.remoteStore),await this.persistence.li(()=>(this.gcScheduler&&!this.gcScheduler.started&&this.gcScheduler.start(),this.indexBackfillerScheduler&&!this.indexBackfillerScheduler.started&&this.indexBackfillerScheduler.start(),Promise.resolve()))}Ic(e){var t,n,r,i;return t=this.persistence,n=new o3,r=e.initialUser,i=this.yt,new o4(t,n,r,i)}Tc(e,t){let n=this.persistence.referenceDelegate.garbageCollector;return new oE(n,e.asyncQueue,t)}Ec(e,t){let n=new rC(t,this.persistence);return new rA(e.asyncQueue,n)}yc(e){let t=o1(e.databaseInfo.databaseId,e.databaseInfo.persistenceKey),n=void 0!==this.cacheSizeBytes?ou.withCacheSize(this.cacheSizeBytes):ou.DEFAULT;return new oJ(this.synchronizeTabs,t,e.clientId,n,e.asyncQueue,lb(),lI(),this.yt,this.sharedClientState,!!this.forceOwnership)}gc(e){return new lm}}class uW extends uK{constructor(e,t){super(e,t,!1),this.Ac=e,this.cacheSizeBytes=t,this.synchronizeTabs=!0}async initialize(e){await super.initialize(e);let t=this.Ac.syncEngine;this.sharedClientState instanceof lp&&(this.sharedClientState.syncEngine={Fr:uM.bind(null,t),$r:uB.bind(null,t),Br:uj.bind(null,t),vi:uq.bind(null,t),Mr:uL.bind(null,t)},await this.sharedClientState.start()),await this.persistence.li(async e=>{await uU(this.Ac.syncEngine,e),this.gcScheduler&&(e&&!this.gcScheduler.started?this.gcScheduler.start():e||this.gcScheduler.stop()),this.indexBackfillerScheduler&&(e&&!this.indexBackfillerScheduler.started?this.indexBackfillerScheduler.start():e||this.indexBackfillerScheduler.stop())})}gc(e){let t=lb();if(!lp.C(t))throw new nQ(nH.UNIMPLEMENTED,"IndexedDB persistence is only available on platforms that support LocalStorage.");let n=o1(e.databaseInfo.databaseId,e.databaseInfo.persistenceKey);return new lp(t,e.asyncQueue,n,e.clientId,e.initialUser)}}class uH{async initialize(e,t){this.localStore||(this.localStore=e.localStore,this.sharedClientState=e.sharedClientState,this.datastore=this.createDatastore(t),this.remoteStore=this.createRemoteStore(t),this.eventManager=this.createEventManager(t),this.syncEngine=this.createSyncEngine(t,!e.synchronizeTabs),this.sharedClientState.onlineStateHandler=e=>u_(this.syncEngine,e,1),this.remoteStore.remoteSyncer.handleCredentialChange=uD.bind(null,this.syncEngine),await lZ(this.remoteStore,this.syncEngine.isPrimaryClient))}createEventManager(e){return new l8}createDatastore(e){var t,n,r;let i=lT(e.databaseInfo.databaseId),s=(t=e.databaseInfo,new l_(t));return n=e.authCredentials,r=e.appCheckCredentials,new lC(n,r,s,i)}createRemoteStore(e){var t,n,r,i,s;return t=this.localStore,n=this.datastore,r=e.asyncQueue,i=e=>u_(this.syncEngine,e,0),s=ly.C()?new ly:new lg,new lN(t,n,r,i,s)}createSyncEngine(e,t){return function(e,t,n,r,i,s,a){let o=new up(e,t,n,r,i,s);return a&&(o.dc=!0),o}(this.localStore,this.remoteStore,this.eventManager,this.sharedClientState,e.initialUser,e.maxConcurrentLimboResolutions,t)}terminate(){return async function(e){nj("RemoteStore","RemoteStore shutting down."),e._u.add(5),await lD(e),e.mu.shutdown(),e.gu.set("Unknown")}(this.remoteStore)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function uQ(e,t,n){if(!n)throw new nQ(nH.INVALID_ARGUMENT,`Function ${e}() cannot be called with an empty ${t}.`)}function uY(e,t,n,r){if(!0===t&&!0===r)throw new nQ(nH.INVALID_ARGUMENT,`${e} and ${n} cannot be used together.`)}function uX(e){if(!ri.isDocumentKey(e))throw new nQ(nH.INVALID_ARGUMENT,`Invalid document reference. Document references must have an even number of segments, but ${e} has ${e.length}.`)}function uJ(e){if(ri.isDocumentKey(e))throw new nQ(nH.INVALID_ARGUMENT,`Invalid collection reference. Collection references must have an odd number of segments, but ${e} has ${e.length}.`)}function uZ(e){if(void 0===e)return"undefined";if(null===e)return"null";if("string"==typeof e)return e.length>20&&(e=`${e.substring(0,20)}...`),JSON.stringify(e);if("number"==typeof e||"boolean"==typeof e)return""+e;if("object"==typeof e){if(e instanceof Array)return"an array";{var t;let n=(t=e).constructor?t.constructor.name:null;return n?`a custom ${n} object`:"an object"}}return"function"==typeof e?"a function":nK()}function u0(e,t){if("_delegate"in e&&(e=e._delegate),!(e instanceof t)){if(t.name===e.constructor.name)throw new nQ(nH.INVALID_ARGUMENT,"Type does not match the expected instance. Did you pass a reference from a different Firestore SDK?");{let n=uZ(e);throw new nQ(nH.INVALID_ARGUMENT,`Expected type '${t.name}', but it was: ${n}`)}}return e}function u1(e,t){if(t<=0)throw new nQ(nH.INVALID_ARGUMENT,`Function ${e}() requires a positive number, but it was: ${t}.`)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let u2=new Map;class u3{constructor(e){var t;if(void 0===e.host){if(void 0!==e.ssl)throw new nQ(nH.INVALID_ARGUMENT,"Can't provide ssl option if host option is not set");this.host="firestore.googleapis.com",this.ssl=!0}else this.host=e.host,this.ssl=null===(t=e.ssl)||void 0===t||t;if(this.credentials=e.credentials,this.ignoreUndefinedProperties=!!e.ignoreUndefinedProperties,void 0===e.cacheSizeBytes)this.cacheSizeBytes=41943040;else{if(-1!==e.cacheSizeBytes&&e.cacheSizeBytes<1048576)throw new nQ(nH.INVALID_ARGUMENT,"cacheSizeBytes must be at least 1048576");this.cacheSizeBytes=e.cacheSizeBytes}this.experimentalForceLongPolling=!!e.experimentalForceLongPolling,this.experimentalAutoDetectLongPolling=!!e.experimentalAutoDetectLongPolling,this.useFetchStreams=!!e.useFetchStreams,uY("experimentalForceLongPolling",e.experimentalForceLongPolling,"experimentalAutoDetectLongPolling",e.experimentalAutoDetectLongPolling)}isEqual(e){return this.host===e.host&&this.ssl===e.ssl&&this.credentials===e.credentials&&this.cacheSizeBytes===e.cacheSizeBytes&&this.experimentalForceLongPolling===e.experimentalForceLongPolling&&this.experimentalAutoDetectLongPolling===e.experimentalAutoDetectLongPolling&&this.ignoreUndefinedProperties===e.ignoreUndefinedProperties&&this.useFetchStreams===e.useFetchStreams}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class u4{constructor(e,t,n,r){this._authCredentials=e,this._appCheckCredentials=t,this._databaseId=n,this._app=r,this.type="firestore-lite",this._persistenceKey="(lite)",this._settings=new u3({}),this._settingsFrozen=!1}get app(){if(!this._app)throw new nQ(nH.FAILED_PRECONDITION,"Firestore was not initialized using the Firebase SDK. 'app' is not available");return this._app}get _initialized(){return this._settingsFrozen}get _terminated(){return void 0!==this._terminateTask}_setSettings(e){if(this._settingsFrozen)throw new nQ(nH.FAILED_PRECONDITION,"Firestore has already been started and its settings can no longer be changed. You can only modify settings before calling any other methods on a Firestore object.");this._settings=new u3(e),void 0!==e.credentials&&(this._authCredentials=function(e){if(!e)return new nJ;switch(e.type){case"gapi":let t=e.client;return new n2(t,e.sessionIndex||"0",e.iamToken||null,e.authTokenFactory||null);case"provider":return e.client;default:throw new nQ(nH.INVALID_ARGUMENT,"makeAuthCredentialsProvider failed due to invalid credential type")}}(e.credentials))}_getSettings(){return this._settings}_freezeSettings(){return this._settingsFrozen=!0,this._settings}_delete(){return this._terminateTask||(this._terminateTask=this._terminate()),this._terminateTask}toJSON(){return{app:this._app,databaseId:this._databaseId,settings:this._settings}}_terminate(){return function(e){let t=u2.get(e);t&&(nj("ComponentProvider","Removing Datastore"),u2.delete(e),t.terminate())}(this),Promise.resolve()}}function u6(e,t,n,r={}){var i;let s=(e=u0(e,u4))._getSettings();if("firestore.googleapis.com"!==s.host&&s.host!==t&&n$("Host has been set in both settings() and useEmulator(), emulator host will be used"),e._setSettings(Object.assign(Object.assign({},s),{host:`${t}:${n}`,ssl:!1})),r.mockUserToken){let t,n;if("string"==typeof r.mockUserToken)t=r.mockUserToken,n=nU.MOCK_USER;else{t=(0,p.Sg)(r.mockUserToken,null===(i=e._app)||void 0===i?void 0:i.options.projectId);let s=r.mockUserToken.sub||r.mockUserToken.user_id;if(!s)throw new nQ(nH.INVALID_ARGUMENT,"mockUserToken must contain 'sub' or 'user_id' field!");n=new nU(s)}e._authCredentials=new nZ(new nX(t,n))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class u5{constructor(e,t,n){this.converter=t,this._key=n,this.type="document",this.firestore=e}get _path(){return this._key.path}get id(){return this._key.path.lastSegment()}get path(){return this._key.path.canonicalString()}get parent(){return new u8(this.firestore,this.converter,this._key.path.popLast())}withConverter(e){return new u5(this.firestore,e,this._key)}}class u9{constructor(e,t,n){this.converter=t,this._query=n,this.type="query",this.firestore=e}withConverter(e){return new u9(this.firestore,e,this._query)}}class u8 extends u9{constructor(e,t,n){super(e,t,iq(n)),this._path=n,this.type="collection"}get id(){return this._query.path.lastSegment()}get path(){return this._query.path.canonicalString()}get parent(){let e=this._path.popLast();return e.isEmpty()?null:new u5(this.firestore,null,new ri(e))}withConverter(e){return new u8(this.firestore,e,this._path)}}function u7(e,t,...n){if(e=(0,p.m9)(e),uQ("collection","path",t),e instanceof u4){let r=rt.fromString(t,...n);return uJ(r),new u8(e,null,r)}{if(!(e instanceof u5||e instanceof u8))throw new nQ(nH.INVALID_ARGUMENT,"Expected first argument to collection() to be a CollectionReference, a DocumentReference or FirebaseFirestore");let r=e._path.child(rt.fromString(t,...n));return uJ(r),new u8(e.firestore,null,r)}}function ce(e,t){if(e=u0(e,u4),uQ("collectionGroup","collection id",t),t.indexOf("/")>=0)throw new nQ(nH.INVALID_ARGUMENT,`Invalid collection ID '${t}' passed to function collectionGroup(). Collection IDs must not contain '/'.`);return new u9(e,null,new iV(rt.emptyPath(),t))}function ct(e,t,...n){if(e=(0,p.m9)(e),1==arguments.length&&(t=n6.R()),uQ("doc","path",t),e instanceof u4){let r=rt.fromString(t,...n);return uX(r),new u5(e,null,new ri(r))}{if(!(e instanceof u5||e instanceof u8))throw new nQ(nH.INVALID_ARGUMENT,"Expected first argument to collection() to be a CollectionReference, a DocumentReference or FirebaseFirestore");let r=e._path.child(rt.fromString(t,...n));return uX(r),new u5(e.firestore,e instanceof u8?e.converter:null,new ri(r))}}function cn(e,t){return e=(0,p.m9)(e),t=(0,p.m9)(t),(e instanceof u5||e instanceof u8)&&(t instanceof u5||t instanceof u8)&&e.firestore===t.firestore&&e.path===t.path&&e.converter===t.converter}function cr(e,t){return e=(0,p.m9)(e),t=(0,p.m9)(t),e instanceof u9&&t instanceof u9&&e.firestore===t.firestore&&iQ(e._query,t._query)&&e.converter===t.converter}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ci(e,t=10240){let n=0;return{async read(){if(n<e.byteLength){let r={value:e.slice(n,n+t),done:!1};return n+=t,r}return{done:!0}},async cancel(){},releaseLock(){},closed:Promise.reject("unimplemented")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cs{constructor(e){this.observer=e,this.muted=!1}next(e){this.observer.next&&this.Rc(this.observer.next,e)}error(e){this.observer.error?this.Rc(this.observer.error,e):nz("Uncaught Error in snapshot listener:",e.toString())}bc(){this.muted=!0}Rc(e,t){this.muted||setTimeout(()=>{this.muted||e(t)},0)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ca{constructor(e,t){this.Pc=e,this.yt=t,this.metadata=new nY,this.buffer=new Uint8Array,this.vc=new TextDecoder("utf-8"),this.Vc().then(e=>{e&&e.Ou()?this.metadata.resolve(e.ku.metadata):this.metadata.reject(Error(`The first element of the bundle is not a metadata, it is
             ${JSON.stringify(null==e?void 0:e.ku)}`))},e=>this.metadata.reject(e))}close(){return this.Pc.cancel()}async getMetadata(){return this.metadata.promise}async mc(){return await this.getMetadata(),this.Vc()}async Vc(){let e=await this.Sc();if(null===e)return null;let t=this.vc.decode(e),n=Number(t);isNaN(n)&&this.Dc(`length string (${t}) is not valid number`);let r=await this.Cc(n);return new us(JSON.parse(r),e.length+n)}xc(){return this.buffer.findIndex(e=>123===e)}async Sc(){for(;0>this.xc()&&!await this.Nc(););if(0===this.buffer.length)return null;let e=this.xc();e<0&&this.Dc("Reached the end of bundle when a length string is expected.");let t=this.buffer.slice(0,e);return this.buffer=this.buffer.slice(e),t}async Cc(e){for(;this.buffer.length<e;)await this.Nc()&&this.Dc("Reached the end of bundle when more is expected.");let t=this.vc.decode(this.buffer.slice(0,e));return this.buffer=this.buffer.slice(e),t}Dc(e){throw this.Pc.cancel(),Error(`Invalid bundle format: ${e}`)}async Nc(){let e=await this.Pc.read();if(!e.done){let t=new Uint8Array(this.buffer.length+e.value.length);t.set(this.buffer),t.set(e.value,this.buffer.length),this.buffer=t}return e.done}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class co{constructor(e){this.datastore=e,this.readVersions=new Map,this.mutations=[],this.committed=!1,this.lastWriteError=null,this.writtenDocs=new Set}async lookup(e){if(this.ensureCommitNotCalled(),this.mutations.length>0)throw new nQ(nH.INVALID_ARGUMENT,"Firestore transactions require all reads to be executed before all writes.");let t=await async function(e,t){let n=s0(e.yt)+"/documents",r={documents:t.map(t=>sY(e.yt,t))},i=await e._o("BatchGetDocuments",n,r,t.length),s=new Map;i.forEach(t=>{var n;let r=(n=e.yt,"found"in t?function(e,t){t.found||nK(),t.found.name,t.found.updateTime;let n=sX(e,t.found.name),r=sW(t.found.updateTime),i=t.found.createTime?sW(t.found.createTime):n7.min(),s=new ix({mapValue:{fields:t.found.fields}});return iN.newFoundDocument(n,r,i,s)}(n,t):"missing"in t?function(e,t){t.missing||nK(),t.readTime||nK();let n=sX(e,t.missing),r=sW(t.readTime);return iN.newNoDocument(n,r)}(n,t):nK());s.set(r.key.toString(),r)});let a=[];return t.forEach(e=>{let t=s.get(e.toString());t||nK(),a.push(t)}),a}(this.datastore,e);return t.forEach(e=>this.recordVersion(e)),t}set(e,t){this.write(t.toMutation(e,this.precondition(e))),this.writtenDocs.add(e.toString())}update(e,t){try{this.write(t.toMutation(e,this.preconditionForUpdate(e)))}catch(e){this.lastWriteError=e}this.writtenDocs.add(e.toString())}delete(e){this.write(new sy(e,this.precondition(e))),this.writtenDocs.add(e.toString())}async commit(){if(this.ensureCommitNotCalled(),this.lastWriteError)throw this.lastWriteError;let e=this.readVersions;this.mutations.forEach(t=>{e.delete(t.key.toString())}),e.forEach((e,t)=>{let n=ri.fromPath(t);this.mutations.push(new sv(n,this.precondition(n)))}),await async function(e,t){let n=s0(e.yt)+"/documents",r={writes:t.map(t=>s4(e.yt,t))};await e.ao("Commit",n,r)}(this.datastore,this.mutations),this.committed=!0}recordVersion(e){let t;if(e.isFoundDocument())t=e.version;else{if(!e.isNoDocument())throw nK();t=n7.min()}let n=this.readVersions.get(e.key.toString());if(n){if(!t.isEqual(n))throw new nQ(nH.ABORTED,"Document version changed between two reads.")}else this.readVersions.set(e.key.toString(),t)}precondition(e){let t=this.readVersions.get(e.toString());return!this.writtenDocs.has(e.toString())&&t?t.isEqual(n7.min())?sa.exists(!1):sa.updateTime(t):sa.none()}preconditionForUpdate(e){let t=this.readVersions.get(e.toString());if(!this.writtenDocs.has(e.toString())&&t){if(t.isEqual(n7.min()))throw new nQ(nH.INVALID_ARGUMENT,"Can't update a document that doesn't exist.");return sa.updateTime(t)}return sa.exists(!0)}write(e){this.ensureCommitNotCalled(),this.mutations.push(e)}ensureCommitNotCalled(){}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cl{constructor(e,t,n,r,i){this.asyncQueue=e,this.datastore=t,this.options=n,this.updateFunction=r,this.deferred=i,this.kc=n.maxAttempts,this.xo=new lE(this.asyncQueue,"transaction_retry")}run(){this.kc-=1,this.Oc()}Oc(){this.xo.Ro(async()=>{let e=new co(this.datastore),t=this.Mc(e);t&&t.then(t=>{this.asyncQueue.enqueueAndForget(()=>e.commit().then(()=>{this.deferred.resolve(t)}).catch(e=>{this.Fc(e)}))}).catch(e=>{this.Fc(e)})})}Mc(e){try{let t=this.updateFunction(e);return!rL(t)&&t.catch&&t.then?t:(this.deferred.reject(Error("Transaction callback must return a Promise")),null)}catch(e){return this.deferred.reject(e),null}}Fc(e){this.kc>0&&this.$c(e)?(this.kc-=1,this.asyncQueue.enqueueAndForget(()=>(this.Oc(),Promise.resolve()))):this.deferred.reject(e)}$c(e){if("FirebaseError"===e.name){let t=e.code;return"aborted"===t||"failed-precondition"===t||"already-exists"===t||!s_(t)}return!1}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cu{constructor(e,t,n,r){this.authCredentials=e,this.appCheckCredentials=t,this.asyncQueue=n,this.databaseInfo=r,this.user=nU.UNAUTHENTICATED,this.clientId=n6.R(),this.authCredentialListener=()=>Promise.resolve(),this.appCheckCredentialListener=()=>Promise.resolve(),this.authCredentials.start(n,async e=>{nj("FirestoreClient","Received user=",e.uid),await this.authCredentialListener(e),this.user=e}),this.appCheckCredentials.start(n,e=>(nj("FirestoreClient","Received new app check token=",e),this.appCheckCredentialListener(e,this.user)))}async getConfiguration(){return{asyncQueue:this.asyncQueue,databaseInfo:this.databaseInfo,clientId:this.clientId,authCredentials:this.authCredentials,appCheckCredentials:this.appCheckCredentials,initialUser:this.user,maxConcurrentLimboResolutions:100}}setCredentialChangeListener(e){this.authCredentialListener=e}setAppCheckTokenChangeListener(e){this.appCheckCredentialListener=e}verifyNotTerminated(){if(this.asyncQueue.isShuttingDown)throw new nQ(nH.FAILED_PRECONDITION,"The client has already been terminated.")}terminate(){this.asyncQueue.enterRestrictedMode();let e=new nY;return this.asyncQueue.enqueueAndForgetEvenWhileRestricted(async()=>{try{this.onlineComponents&&await this.onlineComponents.terminate(),this.offlineComponents&&await this.offlineComponents.terminate(),this.authCredentials.shutdown(),this.appCheckCredentials.shutdown(),e.resolve()}catch(n){let t=l3(n,"Failed to shutdown persistence");e.reject(t)}}),e.promise}}async function cc(e,t){e.asyncQueue.verifyOperationInProgress(),nj("FirestoreClient","Initializing OfflineComponentProvider");let n=await e.getConfiguration();await t.initialize(n);let r=n.initialUser;e.setCredentialChangeListener(async e=>{r.isEqual(e)||(await o6(t.localStore,e),r=e)}),t.persistence.setDatabaseDeletedListener(()=>e.terminate()),e.offlineComponents=t}async function ch(e,t){e.asyncQueue.verifyOperationInProgress();let n=await cd(e);nj("FirestoreClient","Initializing OnlineComponentProvider");let r=await e.getConfiguration();await t.initialize(n,r),e.setCredentialChangeListener(e=>lJ(t.remoteStore,e)),e.setAppCheckTokenChangeListener((e,n)=>lJ(t.remoteStore,n)),e.onlineComponents=t}async function cd(e){return e.offlineComponents||(nj("FirestoreClient","Using default OfflineComponentProvider"),await cc(e,new uG)),e.offlineComponents}async function cf(e){return e.onlineComponents||(nj("FirestoreClient","Using default OnlineComponentProvider"),await ch(e,new uH)),e.onlineComponents}function cp(e){return cd(e).then(e=>e.persistence)}function cm(e){return cd(e).then(e=>e.localStore)}function cg(e){return cf(e).then(e=>e.remoteStore)}function cy(e){return cf(e).then(e=>e.syncEngine)}async function cv(e){let t=await cf(e),n=t.eventManager;return n.onListen=um.bind(null,t.syncEngine),n.onUnlisten=uy.bind(null,t.syncEngine),n}function cw(e,t,n={}){let r=new nY;return e.asyncQueue.enqueueAndForget(async()=>(function(e,t,n,r,i){let s=new cs({next:s=>{t.enqueueAndForget(()=>ue(e,a));let o=s.docs.has(n);!o&&s.fromCache?i.reject(new nQ(nH.UNAVAILABLE,"Failed to get document because the client is offline.")):o&&s.fromCache&&r&&"server"===r.source?i.reject(new nQ(nH.UNAVAILABLE,'Failed to get document from server. (However, this document does exist in the local cache. Run again without setting source to "server" to retrieve the cached document.)')):i.resolve(s)},error:e=>i.reject(e)}),a=new ui(iq(n.path),s,{includeMetadataChanges:!0,Nu:!0});return l7(e,a)})(await cv(e),e.asyncQueue,t,n,r)),r.promise}function c_(e,t,n={}){let r=new nY;return e.asyncQueue.enqueueAndForget(async()=>(function(e,t,n,r,i){let s=new cs({next:n=>{t.enqueueAndForget(()=>ue(e,a)),n.fromCache&&"server"===r.source?i.reject(new nQ(nH.UNAVAILABLE,'Failed to get documents from server. (However, these documents may exist in the local cache. Run again without setting source to "server" to retrieve the cached documents.)')):i.resolve(n)},error:e=>i.reject(e)}),a=new ui(n,s,{includeMetadataChanges:!0,Nu:!0});return l7(e,a)})(await cv(e),e.asyncQueue,t,n,r)),r.promise}class cb{constructor(){this.Bc=Promise.resolve(),this.Lc=[],this.qc=!1,this.Uc=[],this.Kc=null,this.Gc=!1,this.Qc=!1,this.jc=[],this.xo=new lE(this,"async_queue_retry"),this.Wc=()=>{let e=lI();e&&nj("AsyncQueue","Visibility state changed to "+e.visibilityState),this.xo.Po()};let e=lI();e&&"function"==typeof e.addEventListener&&e.addEventListener("visibilitychange",this.Wc)}get isShuttingDown(){return this.qc}enqueueAndForget(e){this.enqueue(e)}enqueueAndForgetEvenWhileRestricted(e){this.zc(),this.Hc(e)}enterRestrictedMode(e){if(!this.qc){this.qc=!0,this.Qc=e||!1;let t=lI();t&&"function"==typeof t.removeEventListener&&t.removeEventListener("visibilitychange",this.Wc)}}enqueue(e){if(this.zc(),this.qc)return new Promise(()=>{});let t=new nY;return this.Hc(()=>this.qc&&this.Qc?Promise.resolve():(e().then(t.resolve,t.reject),t.promise)).then(()=>t.promise)}enqueueRetryable(e){this.enqueueAndForget(()=>(this.Lc.push(e),this.Jc()))}async Jc(){if(0!==this.Lc.length){try{await this.Lc[0](),this.Lc.shift(),this.xo.reset()}catch(e){if(!rI(e))throw e;nj("AsyncQueue","Operation failed with retryable error: "+e)}this.Lc.length>0&&this.xo.Ro(()=>this.Jc())}}Hc(e){let t=this.Bc.then(()=>(this.Gc=!0,e().catch(e=>{let t;this.Kc=e,this.Gc=!1;let n=(t=e.message||"",e.stack&&(t=e.stack.includes(e.message)?e.stack:e.message+"\n"+e.stack),t);throw nz("INTERNAL UNHANDLED ERROR: ",n),e}).then(e=>(this.Gc=!1,e))));return this.Bc=t,t}enqueueAfterDelay(e,t,n){this.zc(),this.jc.indexOf(e)>-1&&(t=0);let r=l2.createAndSchedule(this,e,t,n,e=>this.Yc(e));return this.Uc.push(r),r}zc(){this.Kc&&nK()}verifyOperationInProgress(){}async Xc(){let e;do await (e=this.Bc);while(e!==this.Bc)}Zc(e){for(let t of this.Uc)if(t.timerId===e)return!0;return!1}ta(e){return this.Xc().then(()=>{for(let t of(this.Uc.sort((e,t)=>e.targetTimeMs-t.targetTimeMs),this.Uc))if(t.skipDelay(),"all"!==e&&t.timerId===e)break;return this.Xc()})}ea(e){this.jc.push(e)}Yc(e){let t=this.Uc.indexOf(e);this.Uc.splice(t,1)}}function cI(e){return function(e,t){if("object"!=typeof e||null===e)return!1;for(let n of t)if(n in e&&"function"==typeof e[n])return!0;return!1}(e,["next","error","complete"])}class cT{constructor(){this._progressObserver={},this._taskCompletionResolver=new nY,this._lastProgress={taskState:"Running",totalBytes:0,totalDocuments:0,bytesLoaded:0,documentsLoaded:0}}onProgress(e,t,n){this._progressObserver={next:e,error:t,complete:n}}catch(e){return this._taskCompletionResolver.promise.catch(e)}then(e,t){return this._taskCompletionResolver.promise.then(e,t)}_completeWith(e){this._updateProgress(e),this._progressObserver.complete&&this._progressObserver.complete(),this._taskCompletionResolver.resolve(e)}_failWith(e){this._lastProgress.taskState="Error",this._progressObserver.next&&this._progressObserver.next(this._lastProgress),this._progressObserver.error&&this._progressObserver.error(e),this._taskCompletionResolver.reject(e)}_updateProgress(e){this._lastProgress=e,this._progressObserver.next&&this._progressObserver.next(e)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let cE=-1;class cS extends u4{constructor(e,t,n,r){super(e,t,n,r),this.type="firestore",this._queue=new cb,this._persistenceKey=(null==r?void 0:r.name)||"[DEFAULT]"}_terminate(){return this._firestoreClient||cA(this),this._firestoreClient.terminate()}}function ck(e){return e._firestoreClient||cA(e),e._firestoreClient.verifyNotTerminated(),e._firestoreClient}function cA(e){var t,n,r,i;let s=e._freezeSettings(),a=(n=e._databaseId,r=(null===(t=e._app)||void 0===t?void 0:t.options.appId)||"",i=e._persistenceKey,new rN(n,r,i,s.host,s.ssl,s.experimentalForceLongPolling,s.experimentalAutoDetectLongPolling,s.useFetchStreams));e._firestoreClient=new cu(e._authCredentials,e._appCheckCredentials,e._queue,a)}function cC(e,t){cU(e=u0(e,cS));let n=ck(e),r=e._freezeSettings(),i=new uH;return cN(n,i,new uK(i,r.cacheSizeBytes,null==t?void 0:t.forceOwnership))}function cx(e){cU(e=u0(e,cS));let t=ck(e),n=e._freezeSettings(),r=new uH;return cN(t,r,new uW(r,n.cacheSizeBytes))}function cN(e,t,n){let r=new nY;return e.asyncQueue.enqueue(async()=>{try{await cc(e,n),await ch(e,t),r.resolve()}catch(e){if(!("FirebaseError"===e.name?e.code===nH.FAILED_PRECONDITION||e.code===nH.UNIMPLEMENTED:!("undefined"!=typeof DOMException&&e instanceof DOMException)||22===e.code||20===e.code||11===e.code))throw e;n$("Error enabling offline persistence. Falling back to persistence disabled: "+e),r.reject(e)}}).then(()=>r.promise)}function cR(e){if(e._initialized&&!e._terminated)throw new nQ(nH.FAILED_PRECONDITION,"Persistence can only be cleared before a Firestore instance is initialized or after it is terminated.");let t=new nY;return e._queue.enqueueAndForgetEvenWhileRestricted(async()=>{try{await async function(e){if(!rw.C())return Promise.resolve();await rw.delete(e+"main")}(o1(e._databaseId,e._persistenceKey)),t.resolve()}catch(e){t.reject(e)}}),t.promise}function cD(e){return function(e){let t=new nY;return e.asyncQueue.enqueueAndForget(async()=>uE(await cy(e),t)),t.promise}(ck(e=u0(e,cS)))}function cO(e){var t;return(t=ck(e=u0(e,cS))).asyncQueue.enqueue(async()=>{let e=await cp(t),n=await cg(t);return e.setNetworkEnabled(!0),n._u.delete(0),lR(n)})}function cP(e){var t;return(t=ck(e=u0(e,cS))).asyncQueue.enqueue(async()=>{let e=await cp(t),n=await cg(t);return e.setNetworkEnabled(!1),async function(e){e._u.add(0),await lD(e),e.gu.set("Offline")}(n)})}function cL(e,t){let n=ck(e=u0(e,cS)),r=new cT;return function(e,t,n,r){var i,s;let a=(i=lT(t),s=function(e,t){if(e instanceof Uint8Array)return ci(e,t);if(e instanceof ArrayBuffer)return ci(new Uint8Array(e),t);if(e instanceof ReadableStream)return e.getReader();throw Error("Source of `toByteStreamReader` has to be a ArrayBuffer or ReadableStream")}("string"==typeof n?(new TextEncoder).encode(n):n),new ca(s,i));e.asyncQueue.enqueueAndForget(async()=>{!function(e,t,n){(async function(e,t,n){try{var r;let i=await t.getMetadata();if(await function(e,t){let n=sW(t.createTime);return e.persistence.runTransaction("hasNewerBundle","readonly",n=>e.Ns.getBundleMetadata(n,t.id)).then(e=>!!e&&e.createTime.compareTo(n)>=0)}(e.localStore,i))return await t.close(),n._completeWith({taskState:"Success",documentsLoaded:i.totalDocuments,bytesLoaded:i.totalBytes,totalDocuments:i.totalDocuments,totalBytes:i.totalBytes}),Promise.resolve(new Set);n._updateProgress(ul(i));let s=new uo(i,e.localStore,t.yt),a=await t.mc();for(;a;){let e=await s.Fu(a);e&&n._updateProgress(e),a=await t.mc()}let o=await s.complete();return await uR(e,o.Lu,void 0),await (r=e.localStore).persistence.runTransaction("Save bundle","readwrite",e=>r.Ns.saveBundleMetadata(e,i)),n._completeWith(o.progress),Promise.resolve(o.Bu)}catch(e){return n$("SyncEngine",`Loading bundle failed with ${e}`),n._failWith(e),Promise.resolve(new Set)}})(e,t,n).then(t=>{e.sharedClientState.notifyBundleLoaded(t)})}(await cy(e),a,r)})}(n,e._databaseId,t,r),r}function cM(e,t){var n;return(n=ck(e=u0(e,cS))).asyncQueue.enqueue(async()=>{var e;return(e=await cm(n)).persistence.runTransaction("Get named query","readonly",n=>e.Ns.getNamedQuery(n,t))}).then(t=>t?new u9(e,null,t.query):null)}function cU(e){if(e._initialized||e._terminated)throw new nQ(nH.FAILED_PRECONDITION,"Firestore has already been started and persistence can no longer be enabled. You can only enable persistence before calling any other methods on a Firestore object.")}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cF{constructor(e){this._byteString=e}static fromBase64String(e){try{return new cF(rV.fromBase64String(e))}catch(e){throw new nQ(nH.INVALID_ARGUMENT,"Failed to construct data from Base64 string: "+e)}}static fromUint8Array(e){return new cF(rV.fromUint8Array(e))}toBase64(){return this._byteString.toBase64()}toUint8Array(){return this._byteString.toUint8Array()}toString(){return"Bytes(base64: "+this.toBase64()+")"}isEqual(e){return this._byteString.isEqual(e._byteString)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cV{constructor(...e){for(let t=0;t<e.length;++t)if(0===e[t].length)throw new nQ(nH.INVALID_ARGUMENT,"Invalid field name at argument $(i + 1). Field names must not be empty.");this._internalPath=new rr(e)}isEqual(e){return this._internalPath.isEqual(e._internalPath)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cq{constructor(e){this._methodName=e}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cB{constructor(e,t){if(!isFinite(e)||e<-90||e>90)throw new nQ(nH.INVALID_ARGUMENT,"Latitude must be a number between -90 and 90, but was: "+e);if(!isFinite(t)||t<-180||t>180)throw new nQ(nH.INVALID_ARGUMENT,"Longitude must be a number between -180 and 180, but was: "+t);this._lat=e,this._long=t}get latitude(){return this._lat}get longitude(){return this._long}isEqual(e){return this._lat===e._lat&&this._long===e._long}toJSON(){return{latitude:this._lat,longitude:this._long}}_compareTo(e){return n5(this._lat,e._lat)||n5(this._long,e._long)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let cj=/^__.*__$/;class cz{constructor(e,t,n){this.data=e,this.fieldMask=t,this.fieldTransforms=n}toMutation(e,t){return null!==this.fieldMask?new sf(e,this.data,this.fieldMask,t,this.fieldTransforms):new sd(e,this.data,t,this.fieldTransforms)}}class c${constructor(e,t,n){this.data=e,this.fieldMask=t,this.fieldTransforms=n}toMutation(e,t){return new sf(e,this.data,this.fieldMask,t,this.fieldTransforms)}}function cG(e){switch(e){case 0:case 2:case 1:return!0;case 3:case 4:return!1;default:throw nK()}}class cK{constructor(e,t,n,r,i,s){this.settings=e,this.databaseId=t,this.yt=n,this.ignoreUndefinedProperties=r,void 0===i&&this.na(),this.fieldTransforms=i||[],this.fieldMask=s||[]}get path(){return this.settings.path}get sa(){return this.settings.sa}ia(e){return new cK(Object.assign(Object.assign({},this.settings),e),this.databaseId,this.yt,this.ignoreUndefinedProperties,this.fieldTransforms,this.fieldMask)}ra(e){var t;let n=null===(t=this.path)||void 0===t?void 0:t.child(e),r=this.ia({path:n,oa:!1});return r.ua(e),r}ca(e){var t;let n=null===(t=this.path)||void 0===t?void 0:t.child(e),r=this.ia({path:n,oa:!1});return r.na(),r}aa(e){return this.ia({path:void 0,oa:!0})}ha(e){return hn(e,this.settings.methodName,this.settings.la||!1,this.path,this.settings.fa)}contains(e){return void 0!==this.fieldMask.find(t=>e.isPrefixOf(t))||void 0!==this.fieldTransforms.find(t=>e.isPrefixOf(t.field))}na(){if(this.path)for(let e=0;e<this.path.length;e++)this.ua(this.path.get(e))}ua(e){if(0===e.length)throw this.ha("Document fields must not be empty");if(cG(this.sa)&&cj.test(e))throw this.ha('Document fields cannot begin and end with "__"')}}class cW{constructor(e,t,n){this.databaseId=e,this.ignoreUndefinedProperties=t,this.yt=n||lT(e)}da(e,t,n,r=!1){return new cK({sa:e,methodName:t,fa:n,path:rr.emptyPath(),oa:!1,la:r},this.databaseId,this.yt,this.ignoreUndefinedProperties)}}function cH(e){let t=e._freezeSettings(),n=lT(e._databaseId);return new cW(e._databaseId,!!t.ignoreUndefinedProperties,n)}function cQ(e,t,n,r,i,s={}){let a,o;let l=e.da(s.merge||s.mergeFields?2:0,t,n,i);c8("Data must be an object, but it was:",l,r);let u=c5(r,l);if(s.merge)a=new iC(l.fieldMask),o=l.fieldTransforms;else if(s.mergeFields){let e=[];for(let r of s.mergeFields){let i=c7(t,r,n);if(!l.contains(i))throw new nQ(nH.INVALID_ARGUMENT,`Field '${i}' is specified in your field mask but missing from your input data.`);hr(e,i)||e.push(i)}a=new iC(e),o=l.fieldTransforms.filter(e=>a.covers(e.field))}else a=null,o=l.fieldTransforms;return new cz(new ix(u),a,o)}class cY extends cq{_toFieldTransform(e){if(2!==e.sa)throw 1===e.sa?e.ha(`${this._methodName}() can only appear at the top level of your update data`):e.ha(`${this._methodName}() cannot be used with set() unless you pass {merge:true}`);return e.fieldMask.push(e.path),null}isEqual(e){return e instanceof cY}}function cX(e,t,n){return new cK({sa:3,fa:t.settings.fa,methodName:e._methodName,oa:n},t.databaseId,t.yt,t.ignoreUndefinedProperties)}class cJ extends cq{_toFieldTransform(e){return new si(e.path,new i5)}isEqual(e){return e instanceof cJ}}class cZ extends cq{constructor(e,t){super(e),this._a=t}_toFieldTransform(e){let t=cX(this,e,!0),n=this._a.map(e=>c6(e,t)),r=new i9(n);return new si(e.path,r)}isEqual(e){return this===e}}class c0 extends cq{constructor(e,t){super(e),this._a=t}_toFieldTransform(e){let t=cX(this,e,!0),n=this._a.map(e=>c6(e,t)),r=new i7(n);return new si(e.path,r)}isEqual(e){return this===e}}class c1 extends cq{constructor(e,t){super(e),this.wa=t}_toFieldTransform(e){let t=new st(e.yt,i3(e.yt,this.wa));return new si(e.path,t)}isEqual(e){return this===e}}function c2(e,t,n,r){let i=e.da(1,t,n);c8("Data must be an object, but it was:",i,r);let s=[],a=ix.empty();rO(r,(e,r)=>{let o=ht(t,e,n);r=(0,p.m9)(r);let l=i.ca(o);if(r instanceof cY)s.push(o);else{let e=c6(r,l);null!=e&&(s.push(o),a.set(o,e))}});let o=new iC(s);return new c$(a,o,i.fieldTransforms)}function c3(e,t,n,r,i,s){let a=e.da(1,t,n),o=[c7(t,r,n)],l=[i];if(s.length%2!=0)throw new nQ(nH.INVALID_ARGUMENT,`Function ${t}() needs to be called with an even number of arguments that alternate between field names and values.`);for(let e=0;e<s.length;e+=2)o.push(c7(t,s[e])),l.push(s[e+1]);let u=[],c=ix.empty();for(let e=o.length-1;e>=0;--e)if(!hr(u,o[e])){let t=o[e],n=l[e];n=(0,p.m9)(n);let r=a.ca(t);if(n instanceof cY)u.push(t);else{let e=c6(n,r);null!=e&&(u.push(t),c.set(t,e))}}let h=new iC(u);return new c$(c,h,a.fieldTransforms)}function c4(e,t,n,r=!1){return c6(n,e.da(r?4:3,t))}function c6(e,t){if(c9(e=(0,p.m9)(e)))return c8("Unsupported field value:",t,e),c5(e,t);if(e instanceof cq)return function(e,t){if(!cG(t.sa))throw t.ha(`${e._methodName}() can only be used with update() and set()`);if(!t.path)throw t.ha(`${e._methodName}() is not currently supported inside arrays`);let n=e._toFieldTransform(t);n&&t.fieldTransforms.push(n)}(e,t),null;if(void 0===e&&t.ignoreUndefinedProperties)return null;if(t.path&&t.fieldMask.push(t.path),e instanceof Array){if(t.settings.oa&&4!==t.sa)throw t.ha("Nested arrays are not supported");return function(e,t){let n=[],r=0;for(let i of e){let e=c6(i,t.aa(r));null==e&&(e={nullValue:"NULL_VALUE"}),n.push(e),r++}return{arrayValue:{values:n}}}(e,t)}return function(e,t){if(null===(e=(0,p.m9)(e)))return{nullValue:"NULL_VALUE"};if("number"==typeof e)return i3(t.yt,e);if("boolean"==typeof e)return{booleanValue:e};if("string"==typeof e)return{stringValue:e};if(e instanceof Date){let n=n8.fromDate(e);return{timestampValue:sG(t.yt,n)}}if(e instanceof n8){let n=new n8(e.seconds,1e3*Math.floor(e.nanoseconds/1e3));return{timestampValue:sG(t.yt,n)}}if(e instanceof cB)return{geoPointValue:{latitude:e.latitude,longitude:e.longitude}};if(e instanceof cF)return{bytesValue:sK(t.yt,e._byteString)};if(e instanceof u5){let n=t.databaseId,r=e.firestore._databaseId;if(!r.isEqual(n))throw t.ha(`Document reference is for database ${r.projectId}/${r.database} but should be for database ${n.projectId}/${n.database}`);return{referenceValue:sH(e.firestore._databaseId||t.databaseId,e._key.path)}}throw t.ha(`Unsupported field value: ${uZ(e)}`)}(e,t)}function c5(e,t){let n={};return rP(e)?t.path&&t.path.length>0&&t.fieldMask.push(t.path):rO(e,(e,r)=>{let i=c6(r,t.ra(e));null!=i&&(n[e]=i)}),{mapValue:{fields:n}}}function c9(e){return!("object"!=typeof e||null===e||e instanceof Array||e instanceof Date||e instanceof n8||e instanceof cB||e instanceof cF||e instanceof u5||e instanceof cq)}function c8(e,t,n){if(!c9(n)||!("object"==typeof n&&null!==n&&(Object.getPrototypeOf(n)===Object.prototype||null===Object.getPrototypeOf(n)))){let r=uZ(n);throw"an object"===r?t.ha(e+" a custom object"):t.ha(e+" "+r)}}function c7(e,t,n){if((t=(0,p.m9)(t))instanceof cV)return t._internalPath;if("string"==typeof t)return ht(e,t);throw hn("Field path arguments must be of type string or ",e,!1,void 0,n)}let he=RegExp("[~\\*/\\[\\]]");function ht(e,t,n){if(t.search(he)>=0)throw hn(`Invalid field path (${t}). Paths must not contain '~', '*', '/', '[', or ']'`,e,!1,void 0,n);try{return new cV(...t.split("."))._internalPath}catch(r){throw hn(`Invalid field path (${t}). Paths must not be empty, begin with '.', end with '.', or contain '..'`,e,!1,void 0,n)}}function hn(e,t,n,r,i){let s=r&&!r.isEmpty(),a=void 0!==i,o=`Function ${t}() called with invalid data`;n&&(o+=" (via `toFirestore()`)"),o+=". ";let l="";return(s||a)&&(l+=" (found",s&&(l+=` in field ${r}`),a&&(l+=` in document ${i}`),l+=")"),new nQ(nH.INVALID_ARGUMENT,o+e+l)}function hr(e,t){return e.some(e=>e.isEqual(t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hi{constructor(e,t,n,r,i){this._firestore=e,this._userDataWriter=t,this._key=n,this._document=r,this._converter=i}get id(){return this._key.path.lastSegment()}get ref(){return new u5(this._firestore,this._converter,this._key)}exists(){return null!==this._document}data(){if(this._document){if(this._converter){let e=new hs(this._firestore,this._userDataWriter,this._key,this._document,null);return this._converter.fromFirestore(e)}return this._userDataWriter.convertValue(this._document.data.value)}}get(e){if(this._document){let t=this._document.data.field(ha("DocumentSnapshot.get",e));if(null!==t)return this._userDataWriter.convertValue(t)}}}class hs extends hi{data(){return super.data()}}function ha(e,t){return"string"==typeof t?ht(e,t):t instanceof cV?t._internalPath:t._delegate._internalPath}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ho(e){if("L"===e.limitType&&0===e.explicitOrderBy.length)throw new nQ(nH.UNIMPLEMENTED,"limitToLast() queries require specifying at least one orderBy() clause")}class hl{}class hu extends hl{}function hc(e,t,...n){let r=[];for(let i of(t instanceof hl&&r.push(t),function(e){let t=e.filter(e=>e instanceof hf).length,n=e.filter(e=>e instanceof hh).length;if(t>1||t>0&&n>0)throw new nQ(nH.INVALID_ARGUMENT,"InvalidQuery. When using composite filters, you cannot use more than one filter at the top level. Consider nesting the multiple filters within an `and(...)` statement. For example: change `query(query, where(...), or(...))` to `query(query, and(where(...), or(...)))`.")}(r=r.concat(n)),r))e=i._apply(e);return e}class hh extends hu{constructor(e,t,n){super(),this._field=e,this._op=t,this._value=n,this.type="where"}static _create(e,t,n){return new hh(e,t,n)}_apply(e){let t=this._parse(e);return hC(e._query,t),new u9(e.firestore,e.converter,iW(e._query,t))}_parse(e){let t=cH(e.firestore),n=function(e,t,n,r,i,s,a){let o;if(i.isKeyField()){if("array-contains"===s||"array-contains-any"===s)throw new nQ(nH.INVALID_ARGUMENT,`Invalid Query. You can't perform '${s}' queries on documentId().`);if("in"===s||"not-in"===s){hA(a,s);let t=[];for(let n of a)t.push(hk(r,e,n));o={arrayValue:{values:t}}}else o=hk(r,e,a)}else"in"!==s&&"not-in"!==s&&"array-contains-any"!==s||hA(a,s),o=c4(n,t,a,"in"===s||"not-in"===s);return is.create(i,s,o)}(e._query,"where",t,e.firestore._databaseId,this._field,this._op,this._value);return n}}function hd(e,t,n){let r=ha("where",e);return hh._create(r,t,n)}class hf extends hl{constructor(e,t){super(),this.type=e,this._queryConstraints=t}static _create(e,t){return new hf(e,t)}_parse(e){let t=this._queryConstraints.map(t=>t._parse(e)).filter(e=>e.getFilters().length>0);return 1===t.length?t[0]:ia.create(t,this._getOperator())}_apply(e){let t=this._parse(e);return 0===t.getFilters().length?e:(function(e,t){let n=e,r=t.getFlattenedFilters();for(let e of r)hC(n,e),n=iW(n,e)}(e._query,t),new u9(e.firestore,e.converter,iW(e._query,t)))}_getQueryConstraints(){return this._queryConstraints}_getOperator(){return"and"===this.type?"and":"or"}}class hp extends hu{constructor(e,t){super(),this._field=e,this._direction=t,this.type="orderBy"}static _create(e,t){return new hp(e,t)}_apply(e){let t=function(e,t,n){if(null!==e.startAt)throw new nQ(nH.INVALID_ARGUMENT,"Invalid query. You must not call startAt() or startAfter() before calling orderBy().");if(null!==e.endAt)throw new nQ(nH.INVALID_ARGUMENT,"Invalid query. You must not call endAt() or endBefore() before calling orderBy().");let r=new ib(t,n);return function(e,t){if(null===ij(e)){let n=iz(e);null!==n&&hx(e,n,t.field)}}(e,r),r}(e._query,this._field,this._direction);return new u9(e.firestore,e.converter,function(e,t){let n=e.explicitOrderBy.concat([t]);return new iV(e.path,e.collectionGroup,n,e.filters.slice(),e.limit,e.limitType,e.startAt,e.endAt)}(e._query,t))}}function hm(e,t="asc"){let n=ha("orderBy",e);return hp._create(n,t)}class hg extends hu{constructor(e,t,n){super(),this.type=e,this._limit=t,this._limitType=n}static _create(e,t,n){return new hg(e,t,n)}_apply(e){return new u9(e.firestore,e.converter,iH(e._query,this._limit,this._limitType))}}function hy(e){return u1("limit",e),hg._create("limit",e,"F")}function hv(e){return u1("limitToLast",e),hg._create("limitToLast",e,"L")}class hw extends hu{constructor(e,t,n){super(),this.type=e,this._docOrFields=t,this._inclusive=n}static _create(e,t,n){return new hw(e,t,n)}_apply(e){var t;let n=hS(e,this.type,this._docOrFields,this._inclusive);return new u9(e.firestore,e.converter,(t=e._query,new iV(t.path,t.collectionGroup,t.explicitOrderBy.slice(),t.filters.slice(),t.limit,t.limitType,n,t.endAt)))}}function h_(...e){return hw._create("startAt",e,!0)}function hb(...e){return hw._create("startAfter",e,!1)}class hI extends hu{constructor(e,t,n){super(),this.type=e,this._docOrFields=t,this._inclusive=n}static _create(e,t,n){return new hI(e,t,n)}_apply(e){var t;let n=hS(e,this.type,this._docOrFields,this._inclusive);return new u9(e.firestore,e.converter,(t=e._query,new iV(t.path,t.collectionGroup,t.explicitOrderBy.slice(),t.filters.slice(),t.limit,t.limitType,t.startAt,n)))}}function hT(...e){return hI._create("endBefore",e,!1)}function hE(...e){return hI._create("endAt",e,!0)}function hS(e,t,n,r){if(n[0]=(0,p.m9)(n[0]),n[0]instanceof hi)return function(e,t,n,r,i){if(!r)throw new nQ(nH.NOT_FOUND,`Can't use a DocumentSnapshot that doesn't exist for ${n}().`);let s=[];for(let n of iG(e))if(n.field.isKeyField())s.push(r0(t,r.key));else{let e=r.data.field(n.field);if(r$(e))throw new nQ(nH.INVALID_ARGUMENT,'Invalid query. You are trying to start or end a query using a document for which the field "'+n.field+'" is an uncommitted server timestamp. (Since the value of this field is unknown, you cannot start/end a query with it.)');if(null===e){let e=n.field.canonicalString();throw new nQ(nH.INVALID_ARGUMENT,`Invalid query. You are trying to start or end a query using a document for which the field '${e}' (used as the orderBy) does not exist.`)}s.push(e)}return new ie(s,i)}(e._query,e.firestore._databaseId,t,n[0]._document,r);{let i=cH(e.firestore);return function(e,t,n,r,i,s){let a=e.explicitOrderBy;if(i.length>a.length)throw new nQ(nH.INVALID_ARGUMENT,`Too many arguments provided to ${r}(). The number of arguments must be less than or equal to the number of orderBy() clauses`);let o=[];for(let s=0;s<i.length;s++){let l=i[s];if(a[s].field.isKeyField()){if("string"!=typeof l)throw new nQ(nH.INVALID_ARGUMENT,`Invalid query. Expected a string for document ID in ${r}(), but got a ${typeof l}`);if(!i$(e)&&-1!==l.indexOf("/"))throw new nQ(nH.INVALID_ARGUMENT,`Invalid query. When querying a collection and ordering by documentId(), the value passed to ${r}() must be a plain document ID, but '${l}' contains a slash.`);let n=e.path.child(rt.fromString(l));if(!ri.isDocumentKey(n))throw new nQ(nH.INVALID_ARGUMENT,`Invalid query. When querying a collection group and ordering by documentId(), the value passed to ${r}() must result in a valid document path, but '${n}' is not because it contains an odd number of segments.`);let i=new ri(n);o.push(r0(t,i))}else{let e=c4(n,r,l);o.push(e)}}return new ie(o,s)}(e._query,e.firestore._databaseId,i,t,n,r)}}function hk(e,t,n){if("string"==typeof(n=(0,p.m9)(n))){if(""===n)throw new nQ(nH.INVALID_ARGUMENT,"Invalid query. When querying with documentId(), you must provide a valid document ID, but it was an empty string.");if(!i$(t)&&-1!==n.indexOf("/"))throw new nQ(nH.INVALID_ARGUMENT,`Invalid query. When querying a collection by documentId(), you must provide a plain document ID, but '${n}' contains a '/' character.`);let r=t.path.child(rt.fromString(n));if(!ri.isDocumentKey(r))throw new nQ(nH.INVALID_ARGUMENT,`Invalid query. When querying a collection group by documentId(), the value provided must result in a valid document path, but '${r}' is not because it has an odd number of segments (${r.length}).`);return r0(e,new ri(r))}if(n instanceof u5)return r0(e,n._key);throw new nQ(nH.INVALID_ARGUMENT,`Invalid query. When querying with documentId(), you must provide a valid string or a DocumentReference, but it was: ${uZ(n)}.`)}function hA(e,t){if(!Array.isArray(e)||0===e.length)throw new nQ(nH.INVALID_ARGUMENT,`Invalid Query. A non-empty array is required for '${t.toString()}' filters.`);if(e.length>10)throw new nQ(nH.INVALID_ARGUMENT,`Invalid Query. '${t.toString()}' filters support a maximum of 10 elements in the value array.`)}function hC(e,t){if(t.isInequality()){let n=iz(e),r=t.field;if(null!==n&&!n.isEqual(r))throw new nQ(nH.INVALID_ARGUMENT,`Invalid query. All where filters with an inequality (<, <=, !=, not-in, >, or >=) must be on the same field. But you have inequality filters on '${n.toString()}' and '${r.toString()}'`);let i=ij(e);null!==i&&hx(e,r,i)}let n=function(e,t){for(let n of e)for(let e of n.getFlattenedFilters())if(t.indexOf(e.op)>=0)return e.op;return null}(e.filters,function(e){switch(e){case"!=":return["!=","not-in"];case"array-contains":return["array-contains","array-contains-any","not-in"];case"in":return["array-contains-any","in","not-in"];case"array-contains-any":return["array-contains","array-contains-any","in","not-in"];case"not-in":return["array-contains","array-contains-any","in","not-in","!="];default:return[]}}(t.op));if(null!==n)throw n===t.op?new nQ(nH.INVALID_ARGUMENT,`Invalid query. You cannot use more than one '${t.op.toString()}' filter.`):new nQ(nH.INVALID_ARGUMENT,`Invalid query. You cannot use '${t.op.toString()}' filters with '${n.toString()}' filters.`)}function hx(e,t,n){if(!n.isEqual(t))throw new nQ(nH.INVALID_ARGUMENT,`Invalid query. You have a where filter with an inequality (<, <=, !=, not-in, >, or >=) on field '${t.toString()}' and so you must also use '${t.toString()}' as your first argument to orderBy(), but your first orderBy() is on field '${n.toString()}' instead.`)}class hN{convertValue(e,t="none"){switch(rH(e)){case 0:return null;case 1:return e.booleanValue;case 2:return rj(e.integerValue||e.doubleValue);case 3:return this.convertTimestamp(e.timestampValue);case 4:return this.convertServerTimestamp(e,t);case 5:return e.stringValue;case 6:return this.convertBytes(rz(e.bytesValue));case 7:return this.convertReference(e.referenceValue);case 8:return this.convertGeoPoint(e.geoPointValue);case 9:return this.convertArray(e.arrayValue,t);case 10:return this.convertObject(e.mapValue,t);default:throw nK()}}convertObject(e,t){let n={};return rO(e.fields,(e,r)=>{n[e]=this.convertValue(r,t)}),n}convertGeoPoint(e){return new cB(rj(e.latitude),rj(e.longitude))}convertArray(e,t){return(e.values||[]).map(e=>this.convertValue(e,t))}convertServerTimestamp(e,t){switch(t){case"previous":let n=function e(t){let n=t.mapValue.fields.__previous_value__;return r$(n)?e(n):n}(e);return null==n?null:this.convertValue(n,t);case"estimate":return this.convertTimestamp(rG(e));default:return null}}convertTimestamp(e){let t=rB(e);return new n8(t.seconds,t.nanos)}convertDocumentKey(e,t){let n=rt.fromString(e);at(n)||nK();let r=new rR(n.get(1),n.get(3)),i=new ri(n.popFirst(5));return r.isEqual(t)||nz(`Document ${i} contains a document reference within a different database (${r.projectId}/${r.database}) which is not supported. It will be treated as a reference in the current database (${t.projectId}/${t.database}) instead.`),i}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function hR(e,t,n){return e?n&&(n.merge||n.mergeFields)?e.toFirestore(t,n):e.toFirestore(t):t}class hD extends hN{constructor(e){super(),this.firestore=e}convertBytes(e){return new cF(e)}convertReference(e){let t=this.convertDocumentKey(e,this.firestore._databaseId);return new u5(this.firestore,null,t)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hO{constructor(e,t){this.hasPendingWrites=e,this.fromCache=t}isEqual(e){return this.hasPendingWrites===e.hasPendingWrites&&this.fromCache===e.fromCache}}class hP extends hi{constructor(e,t,n,r,i,s){super(e,t,n,r,s),this._firestore=e,this._firestoreImpl=e,this.metadata=i}exists(){return super.exists()}data(e={}){if(this._document){if(this._converter){let t=new hL(this._firestore,this._userDataWriter,this._key,this._document,this.metadata,null);return this._converter.fromFirestore(t,e)}return this._userDataWriter.convertValue(this._document.data.value,e.serverTimestamps)}}get(e,t={}){if(this._document){let n=this._document.data.field(ha("DocumentSnapshot.get",e));if(null!==n)return this._userDataWriter.convertValue(n,t.serverTimestamps)}}}class hL extends hP{data(e={}){return super.data(e)}}class hM{constructor(e,t,n,r){this._firestore=e,this._userDataWriter=t,this._snapshot=r,this.metadata=new hO(r.hasPendingWrites,r.fromCache),this.query=n}get docs(){let e=[];return this.forEach(t=>e.push(t)),e}get size(){return this._snapshot.docs.size}get empty(){return 0===this.size}forEach(e,t){this._snapshot.docs.forEach(n=>{e.call(t,new hL(this._firestore,this._userDataWriter,n.key,n,new hO(this._snapshot.mutatedKeys.has(n.key),this._snapshot.fromCache),this.query.converter))})}docChanges(e={}){let t=!!e.includeMetadataChanges;if(t&&this._snapshot.excludesMetadataChanges)throw new nQ(nH.INVALID_ARGUMENT,"To include metadata changes with your document changes, you must also pass { includeMetadataChanges:true } to onSnapshot().");return this._cachedChanges&&this._cachedChangesIncludeMetadataChanges===t||(this._cachedChanges=function(e,t){if(e._snapshot.oldDocs.isEmpty()){let t=0;return e._snapshot.docChanges.map(n=>{let r=new hL(e._firestore,e._userDataWriter,n.doc.key,n.doc,new hO(e._snapshot.mutatedKeys.has(n.doc.key),e._snapshot.fromCache),e.query.converter);return n.doc,{type:"added",doc:r,oldIndex:-1,newIndex:t++}})}{let n=e._snapshot.oldDocs;return e._snapshot.docChanges.filter(e=>t||3!==e.type).map(t=>{let r=new hL(e._firestore,e._userDataWriter,t.doc.key,t.doc,new hO(e._snapshot.mutatedKeys.has(t.doc.key),e._snapshot.fromCache),e.query.converter),i=-1,s=-1;return 0!==t.type&&(i=n.indexOf(t.doc.key),n=n.delete(t.doc.key)),1!==t.type&&(s=(n=n.add(t.doc)).indexOf(t.doc.key)),{type:function(e){switch(e){case 0:return"added";case 2:case 3:return"modified";case 1:return"removed";default:return nK()}}(t.type),doc:r,oldIndex:i,newIndex:s}})}}(this,t),this._cachedChangesIncludeMetadataChanges=t),this._cachedChanges}}function hU(e,t){return e instanceof hP&&t instanceof hP?e._firestore===t._firestore&&e._key.isEqual(t._key)&&(null===e._document?null===t._document:e._document.isEqual(t._document))&&e._converter===t._converter:e instanceof hM&&t instanceof hM&&e._firestore===t._firestore&&cr(e.query,t.query)&&e.metadata.isEqual(t.metadata)&&e._snapshot.isEqual(t._snapshot)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function hF(e){e=u0(e,u5);let t=u0(e.firestore,cS);return cw(ck(t),e._key).then(n=>hJ(t,e,n))}class hV extends hN{constructor(e){super(),this.firestore=e}convertBytes(e){return new cF(e)}convertReference(e){let t=this.convertDocumentKey(e,this.firestore._databaseId);return new u5(this.firestore,null,t)}}function hq(e){e=u0(e,u5);let t=u0(e.firestore,cS),n=ck(t),r=new hV(t);return(function(e,t){let n=new nY;return e.asyncQueue.enqueueAndForget(async()=>(async function(e,t,n){try{let r=await e.persistence.runTransaction("read document","readonly",n=>e.localDocuments.getDocument(n,t));r.isFoundDocument()?n.resolve(r):r.isNoDocument()?n.resolve(null):n.reject(new nQ(nH.UNAVAILABLE,"Failed to get document from cache. (However, this document may exist on the server. Run again without setting 'source' in the GetOptions to attempt to retrieve the document from the server.)"))}catch(r){let e=l3(r,`Failed to get document '${t} from cache`);n.reject(e)}})(await cm(e),t,n)),n.promise})(n,e._key).then(n=>new hP(t,r,e._key,n,new hO(null!==n&&n.hasLocalMutations,!0),e.converter))}function hB(e){e=u0(e,u5);let t=u0(e.firestore,cS);return cw(ck(t),e._key,{source:"server"}).then(n=>hJ(t,e,n))}function hj(e){e=u0(e,u9);let t=u0(e.firestore,cS),n=ck(t),r=new hV(t);return ho(e._query),c_(n,e._query).then(n=>new hM(t,r,e,n))}function hz(e){e=u0(e,u9);let t=u0(e.firestore,cS),n=ck(t),r=new hV(t);return(function(e,t){let n=new nY;return e.asyncQueue.enqueueAndForget(async()=>(async function(e,t,n){try{let r=await le(e,t,!0),i=new uh(t,r.Hi),s=i.Wu(r.documents),a=i.applyChanges(s,!1);n.resolve(a.snapshot)}catch(r){let e=l3(r,`Failed to execute query '${t} against cache`);n.reject(e)}})(await cm(e),t,n)),n.promise})(n,e._query).then(n=>new hM(t,r,e,n))}function h$(e){e=u0(e,u9);let t=u0(e.firestore,cS),n=ck(t),r=new hV(t);return c_(n,e._query,{source:"server"}).then(n=>new hM(t,r,e,n))}function hG(e,t,n){e=u0(e,u5);let r=u0(e.firestore,cS),i=hR(e.converter,t,n);return hX(r,[cQ(cH(r),"setDoc",e._key,i,null!==e.converter,n).toMutation(e._key,sa.none())])}function hK(e,t,n,...r){let i;e=u0(e,u5);let s=u0(e.firestore,cS),a=cH(s);return i="string"==typeof(t=(0,p.m9)(t))||t instanceof cV?c3(a,"updateDoc",e._key,t,n,r):c2(a,"updateDoc",e._key,t),hX(s,[i.toMutation(e._key,sa.exists(!0))])}function hW(e){return hX(u0(e.firestore,cS),[new sy(e._key,sa.none())])}function hH(e,t){let n=u0(e.firestore,cS),r=ct(e),i=hR(e.converter,t);return hX(n,[cQ(cH(e.firestore),"addDoc",r._key,i,null!==e.converter,{}).toMutation(r._key,sa.exists(!1))]).then(()=>r)}function hQ(e,...t){var n,r,i;let s,a,o;e=(0,p.m9)(e);let l={includeMetadataChanges:!1},u=0;"object"!=typeof t[0]||cI(t[u])||(l=t[u],u++);let c={includeMetadataChanges:l.includeMetadataChanges};if(cI(t[u])){let e=t[u];t[u]=null===(n=e.next)||void 0===n?void 0:n.bind(e),t[u+1]=null===(r=e.error)||void 0===r?void 0:r.bind(e),t[u+2]=null===(i=e.complete)||void 0===i?void 0:i.bind(e)}if(e instanceof u5)a=u0(e.firestore,cS),o=iq(e._key.path),s={next:n=>{t[u]&&t[u](hJ(a,e,n))},error:t[u+1],complete:t[u+2]};else{let n=u0(e,u9);a=u0(n.firestore,cS),o=n._query;let r=new hV(a);s={next:e=>{t[u]&&t[u](new hM(a,r,n,e))},error:t[u+1],complete:t[u+2]},ho(e._query)}return function(e,t,n,r){let i=new cs(r),s=new ui(t,i,n);return e.asyncQueue.enqueueAndForget(async()=>l7(await cv(e),s)),()=>{i.bc(),e.asyncQueue.enqueueAndForget(async()=>ue(await cv(e),s))}}(ck(a),o,c,s)}function hY(e,t){return function(e,t){let n=new cs(t);return e.asyncQueue.enqueueAndForget(async()=>{(await cv(e)).Ru.add(n),n.next()}),()=>{n.bc(),e.asyncQueue.enqueueAndForget(async()=>(function(e,t){e.Ru.delete(t)})(await cv(e),n))}}(ck(e=u0(e,cS)),cI(t)?t:{next:t})}function hX(e,t){return function(e,t){let n=new nY;return e.asyncQueue.enqueueAndForget(async()=>uv(await cy(e),t,n)),n.promise}(ck(e),t)}function hJ(e,t,n){let r=n.docs.get(t._key),i=new hV(e);return new hP(e,i,t._key,r,new hO(n.hasPendingWrites,n.fromCache),t.converter)}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let hZ={maxAttempts:5};/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class h0{constructor(e,t){this._firestore=e,this._commitHandler=t,this._mutations=[],this._committed=!1,this._dataReader=cH(e)}set(e,t,n){this._verifyNotCommitted();let r=h1(e,this._firestore),i=hR(r.converter,t,n),s=cQ(this._dataReader,"WriteBatch.set",r._key,i,null!==r.converter,n);return this._mutations.push(s.toMutation(r._key,sa.none())),this}update(e,t,n,...r){let i;this._verifyNotCommitted();let s=h1(e,this._firestore);return i="string"==typeof(t=(0,p.m9)(t))||t instanceof cV?c3(this._dataReader,"WriteBatch.update",s._key,t,n,r):c2(this._dataReader,"WriteBatch.update",s._key,t),this._mutations.push(i.toMutation(s._key,sa.exists(!0))),this}delete(e){this._verifyNotCommitted();let t=h1(e,this._firestore);return this._mutations=this._mutations.concat(new sy(t._key,sa.none())),this}commit(){return this._verifyNotCommitted(),this._committed=!0,this._mutations.length>0?this._commitHandler(this._mutations):Promise.resolve()}_verifyNotCommitted(){if(this._committed)throw new nQ(nH.FAILED_PRECONDITION,"A write batch can no longer be used after commit() has been called.")}}function h1(e,t){if((e=(0,p.m9)(e)).firestore!==t)throw new nQ(nH.INVALID_ARGUMENT,"Provided document reference is from a different Firestore instance.");return e}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class h2 extends class{constructor(e,t){this._firestore=e,this._transaction=t,this._dataReader=cH(e)}get(e){let t=h1(e,this._firestore),n=new hD(this._firestore);return this._transaction.lookup([t._key]).then(e=>{if(!e||1!==e.length)return nK();let r=e[0];if(r.isFoundDocument())return new hi(this._firestore,n,r.key,r,t.converter);if(r.isNoDocument())return new hi(this._firestore,n,t._key,null,t.converter);throw nK()})}set(e,t,n){let r=h1(e,this._firestore),i=hR(r.converter,t,n),s=cQ(this._dataReader,"Transaction.set",r._key,i,null!==r.converter,n);return this._transaction.set(r._key,s),this}update(e,t,n,...r){let i;let s=h1(e,this._firestore);return i="string"==typeof(t=(0,p.m9)(t))||t instanceof cV?c3(this._dataReader,"Transaction.update",s._key,t,n,r):c2(this._dataReader,"Transaction.update",s._key,t),this._transaction.update(s._key,i),this}delete(e){let t=h1(e,this._firestore);return this._transaction.delete(t._key),this}}{constructor(e,t){super(e,t),this._firestore=e}get(e){let t=h1(e,this._firestore),n=new hV(this._firestore);return super.get(e).then(e=>new hP(this._firestore,n,t._key,e._document,new hO(!1,!1),t.converter))}}function h3(e,t,n){e=u0(e,cS);let r=Object.assign(Object.assign({},hZ),n);return!function(e){if(e.maxAttempts<1)throw new nQ(nH.INVALID_ARGUMENT,"Max attempts must be at least 1")}(r),function(e,t,n){let r=new nY;return e.asyncQueue.enqueueAndForget(async()=>{let i=await cf(e).then(e=>e.datastore);new cl(e.asyncQueue,i,n,t,r).run()}),r.promise}(ck(e),n=>t(new h2(e,n)),r)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function h4(){return new cY("deleteField")}function h6(){return new cJ("serverTimestamp")}function h5(...e){return new cZ("arrayUnion",e)}function h9(...e){return new c0("arrayRemove",e)}function h8(e){return new c1("increment",e)}!function(e,t=!0){nF=h.SDK_VERSION,(0,h._registerComponent)(new d.wA("firestore",(e,{instanceIdentifier:n,options:r})=>{let i=e.getProvider("app").getImmediate(),s=new cS(new n0(e.getProvider("auth-internal")),new n4(e.getProvider("app-check-internal")),function(e,t){if(!Object.prototype.hasOwnProperty.apply(e.options,["projectId"]))throw new nQ(nH.INVALID_ARGUMENT,'"projectId" not provided in firebase.initializeApp.');return new rR(e.options.projectId,t)}(i,n),i);return r=Object.assign({useFetchStreams:t},r),s._setSettings(r),s},"PUBLIC").setMultipleInstances(!0)),(0,h.registerVersion)(nM,"3.8.3",void 0),(0,h.registerVersion)(nM,"3.8.3","esm2017")}()},4444:function(e,t,n){"use strict";n.d(t,{BH:function(){return g},G6:function(){return S},L:function(){return l},LL:function(){return x},Pz:function(){return m},Sg:function(){return y},UG:function(){return _},ZB:function(){return function e(t,n){if(!(n instanceof Object))return n;switch(n.constructor){case Date:return new Date(n.getTime());case Object:void 0===t&&(t={});break;case Array:t=[];break;default:return n}for(let r in n)n.hasOwnProperty(r)&&"__proto__"!==r&&(t[r]=e(t[r],n[r]));return t}},ZR:function(){return C},aH:function(){return p},b$:function(){return T},eu:function(){return A},hl:function(){return k},jU:function(){return b},m9:function(){return q},ne:function(){return U},pd:function(){return M},r3:function(){return R},ru:function(){return I},tV:function(){return u},uI:function(){return w},vZ:function(){return function e(t,n){if(t===n)return!0;let r=Object.keys(t),i=Object.keys(n);for(let s of r){if(!i.includes(s))return!1;let r=t[s],a=n[s];if(O(r)&&O(a)){if(!e(r,a))return!1}else if(r!==a)return!1}for(let e of i)if(!r.includes(e))return!1;return!0}},w1:function(){return E},xO:function(){return P},xb:function(){return D},z$:function(){return v},zd:function(){return L}});var r=n(3454);/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let i=function(e){let t=[],n=0;for(let r=0;r<e.length;r++){let i=e.charCodeAt(r);i<128?t[n++]=i:i<2048?(t[n++]=i>>6|192,t[n++]=63&i|128):(64512&i)==55296&&r+1<e.length&&(64512&e.charCodeAt(r+1))==56320?(i=65536+((1023&i)<<10)+(1023&e.charCodeAt(++r)),t[n++]=i>>18|240,t[n++]=i>>12&63|128,t[n++]=i>>6&63|128,t[n++]=63&i|128):(t[n++]=i>>12|224,t[n++]=i>>6&63|128,t[n++]=63&i|128)}return t},s=function(e){let t=[],n=0,r=0;for(;n<e.length;){let i=e[n++];if(i<128)t[r++]=String.fromCharCode(i);else if(i>191&&i<224){let s=e[n++];t[r++]=String.fromCharCode((31&i)<<6|63&s)}else if(i>239&&i<365){let s=e[n++],a=e[n++],o=e[n++],l=((7&i)<<18|(63&s)<<12|(63&a)<<6|63&o)-65536;t[r++]=String.fromCharCode(55296+(l>>10)),t[r++]=String.fromCharCode(56320+(1023&l))}else{let s=e[n++],a=e[n++];t[r++]=String.fromCharCode((15&i)<<12|(63&s)<<6|63&a)}}return t.join("")},a={byteToCharMap_:null,charToByteMap_:null,byteToCharMapWebSafe_:null,charToByteMapWebSafe_:null,ENCODED_VALS_BASE:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",get ENCODED_VALS(){return this.ENCODED_VALS_BASE+"+/="},get ENCODED_VALS_WEBSAFE(){return this.ENCODED_VALS_BASE+"-_."},HAS_NATIVE_SUPPORT:"function"==typeof atob,encodeByteArray(e,t){if(!Array.isArray(e))throw Error("encodeByteArray takes an array as a parameter");this.init_();let n=t?this.byteToCharMapWebSafe_:this.byteToCharMap_,r=[];for(let t=0;t<e.length;t+=3){let i=e[t],s=t+1<e.length,a=s?e[t+1]:0,o=t+2<e.length,l=o?e[t+2]:0,u=i>>2,c=(3&i)<<4|a>>4,h=(15&a)<<2|l>>6,d=63&l;o||(d=64,s||(h=64)),r.push(n[u],n[c],n[h],n[d])}return r.join("")},encodeString(e,t){return this.HAS_NATIVE_SUPPORT&&!t?btoa(e):this.encodeByteArray(i(e),t)},decodeString(e,t){return this.HAS_NATIVE_SUPPORT&&!t?atob(e):s(this.decodeStringToByteArray(e,t))},decodeStringToByteArray(e,t){this.init_();let n=t?this.charToByteMapWebSafe_:this.charToByteMap_,r=[];for(let t=0;t<e.length;){let i=n[e.charAt(t++)],s=t<e.length,a=s?n[e.charAt(t)]:0;++t;let o=t<e.length,l=o?n[e.charAt(t)]:64;++t;let u=t<e.length,c=u?n[e.charAt(t)]:64;if(++t,null==i||null==a||null==l||null==c)throw Error();let h=i<<2|a>>4;if(r.push(h),64!==l){let e=a<<4&240|l>>2;if(r.push(e),64!==c){let e=l<<6&192|c;r.push(e)}}}return r},init_(){if(!this.byteToCharMap_){this.byteToCharMap_={},this.charToByteMap_={},this.byteToCharMapWebSafe_={},this.charToByteMapWebSafe_={};for(let e=0;e<this.ENCODED_VALS.length;e++)this.byteToCharMap_[e]=this.ENCODED_VALS.charAt(e),this.charToByteMap_[this.byteToCharMap_[e]]=e,this.byteToCharMapWebSafe_[e]=this.ENCODED_VALS_WEBSAFE.charAt(e),this.charToByteMapWebSafe_[this.byteToCharMapWebSafe_[e]]=e,e>=this.ENCODED_VALS_BASE.length&&(this.charToByteMap_[this.ENCODED_VALS_WEBSAFE.charAt(e)]=e,this.charToByteMapWebSafe_[this.ENCODED_VALS.charAt(e)]=e)}}},o=function(e){let t=i(e);return a.encodeByteArray(t,!0)},l=function(e){return o(e).replace(/\./g,"")},u=function(e){try{return a.decodeString(e,!0)}catch(e){console.error("base64Decode failed: ",e)}return null},c=()=>/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */(function(){if("undefined"!=typeof self)return self;if("undefined"!=typeof window)return window;if(void 0!==n.g)return n.g;throw Error("Unable to locate global object.")})().__FIREBASE_DEFAULTS__,h=()=>{if(void 0===r||void 0===r.env)return;let e=r.env.__FIREBASE_DEFAULTS__;if(e)return JSON.parse(e)},d=()=>{let e;if("undefined"==typeof document)return;try{e=document.cookie.match(/__FIREBASE_DEFAULTS__=([^;]+)/)}catch(e){return}let t=e&&u(e[1]);return t&&JSON.parse(t)},f=()=>{try{return c()||h()||d()}catch(e){console.info(`Unable to get __FIREBASE_DEFAULTS__ due to: ${e}`);return}},p=()=>{var e;return null===(e=f())||void 0===e?void 0:e.config},m=e=>{var t;return null===(t=f())||void 0===t?void 0:t[`_${e}`]};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class g{constructor(){this.reject=()=>{},this.resolve=()=>{},this.promise=new Promise((e,t)=>{this.resolve=e,this.reject=t})}wrapCallback(e){return(t,n)=>{t?this.reject(t):this.resolve(n),"function"==typeof e&&(this.promise.catch(()=>{}),1===e.length?e(t):e(t,n))}}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function y(e,t){if(e.uid)throw Error('The "uid" field is no longer supported by mockUserToken. Please use "sub" instead for Firebase Auth User ID.');let n=t||"demo-project",r=e.iat||0,i=e.sub||e.user_id;if(!i)throw Error("mockUserToken must contain 'sub' or 'user_id' field!");let s=Object.assign({iss:`https://securetoken.google.com/${n}`,aud:n,iat:r,exp:r+3600,auth_time:r,sub:i,user_id:i,firebase:{sign_in_provider:"custom",identities:{}}},e);return[l(JSON.stringify({alg:"none",type:"JWT"})),l(JSON.stringify(s)),""].join(".")}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function v(){return"undefined"!=typeof navigator&&"string"==typeof navigator.userAgent?navigator.userAgent:""}function w(){return"undefined"!=typeof window&&!!(window.cordova||window.phonegap||window.PhoneGap)&&/ios|iphone|ipod|ipad|android|blackberry|iemobile/i.test(v())}function _(){var e;let t=null===(e=f())||void 0===e?void 0:e.forceEnvironment;if("node"===t)return!0;if("browser"===t)return!1;try{return"[object process]"===Object.prototype.toString.call(n.g.process)}catch(e){return!1}}function b(){return"object"==typeof self&&self.self===self}function I(){let e="object"==typeof chrome?chrome.runtime:"object"==typeof browser?browser.runtime:void 0;return"object"==typeof e&&void 0!==e.id}function T(){return"object"==typeof navigator&&"ReactNative"===navigator.product}function E(){let e=v();return e.indexOf("MSIE ")>=0||e.indexOf("Trident/")>=0}function S(){return!_()&&navigator.userAgent.includes("Safari")&&!navigator.userAgent.includes("Chrome")}function k(){try{return"object"==typeof indexedDB}catch(e){return!1}}function A(){return new Promise((e,t)=>{try{let n=!0,r="validate-browser-context-for-indexeddb-analytics-module",i=self.indexedDB.open(r);i.onsuccess=()=>{i.result.close(),n||self.indexedDB.deleteDatabase(r),e(!0)},i.onupgradeneeded=()=>{n=!1},i.onerror=()=>{var e;t((null===(e=i.error)||void 0===e?void 0:e.message)||"")}}catch(e){t(e)}})}class C extends Error{constructor(e,t,n){super(t),this.code=e,this.customData=n,this.name="FirebaseError",Object.setPrototypeOf(this,C.prototype),Error.captureStackTrace&&Error.captureStackTrace(this,x.prototype.create)}}class x{constructor(e,t,n){this.service=e,this.serviceName=t,this.errors=n}create(e,...t){let n=t[0]||{},r=`${this.service}/${e}`,i=this.errors[e],s=i?i.replace(N,(e,t)=>{let r=n[t];return null!=r?String(r):`<${t}?>`}):"Error",a=`${this.serviceName}: ${s} (${r}).`,o=new C(r,a,n);return o}}let N=/\{\$([^}]+)}/g;/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function R(e,t){return Object.prototype.hasOwnProperty.call(e,t)}function D(e){for(let t in e)if(Object.prototype.hasOwnProperty.call(e,t))return!1;return!0}function O(e){return null!==e&&"object"==typeof e}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function P(e){let t=[];for(let[n,r]of Object.entries(e))Array.isArray(r)?r.forEach(e=>{t.push(encodeURIComponent(n)+"="+encodeURIComponent(e))}):t.push(encodeURIComponent(n)+"="+encodeURIComponent(r));return t.length?"&"+t.join("&"):""}function L(e){let t={},n=e.replace(/^\?/,"").split("&");return n.forEach(e=>{if(e){let[n,r]=e.split("=");t[decodeURIComponent(n)]=decodeURIComponent(r)}}),t}function M(e){let t=e.indexOf("?");if(!t)return"";let n=e.indexOf("#",t);return e.substring(t,n>0?n:void 0)}function U(e,t){let n=new F(e,t);return n.subscribe.bind(n)}class F{constructor(e,t){this.observers=[],this.unsubscribes=[],this.observerCount=0,this.task=Promise.resolve(),this.finalized=!1,this.onNoObservers=t,this.task.then(()=>{e(this)}).catch(e=>{this.error(e)})}next(e){this.forEachObserver(t=>{t.next(e)})}error(e){this.forEachObserver(t=>{t.error(e)}),this.close(e)}complete(){this.forEachObserver(e=>{e.complete()}),this.close()}subscribe(e,t,n){let r;if(void 0===e&&void 0===t&&void 0===n)throw Error("Missing Observer.");void 0===(r=!function(e,t){if("object"!=typeof e||null===e)return!1;for(let n of t)if(n in e&&"function"==typeof e[n])return!0;return!1}(e,["next","error","complete"])?{next:e,error:t,complete:n}:e).next&&(r.next=V),void 0===r.error&&(r.error=V),void 0===r.complete&&(r.complete=V);let i=this.unsubscribeOne.bind(this,this.observers.length);return this.finalized&&this.task.then(()=>{try{this.finalError?r.error(this.finalError):r.complete()}catch(e){}}),this.observers.push(r),i}unsubscribeOne(e){void 0!==this.observers&&void 0!==this.observers[e]&&(delete this.observers[e],this.observerCount-=1,0===this.observerCount&&void 0!==this.onNoObservers&&this.onNoObservers(this))}forEachObserver(e){if(!this.finalized)for(let t=0;t<this.observers.length;t++)this.sendOne(t,e)}sendOne(e,t){this.task.then(()=>{if(void 0!==this.observers&&void 0!==this.observers[e])try{t(this.observers[e])}catch(e){"undefined"!=typeof console&&console.error&&console.error(e)}})}close(e){this.finalized||(this.finalized=!0,void 0!==e&&(this.finalError=e),this.task.then(()=>{this.observers=void 0,this.onNoObservers=void 0}))}}function V(){}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function q(e){return e&&e._delegate?e._delegate:e}},3454:function(e,t,n){"use strict";var r,i;e.exports=(null==(r=n.g.process)?void 0:r.env)&&"object"==typeof(null==(i=n.g.process)?void 0:i.env)?n.g.process:n(7663)},1118:function(e,t,n){(window.__NEXT_P=window.__NEXT_P||[]).push(["/_app",function(){return n(4945)}])},2373:function(e,t,n){"use strict";n.d(t,{S:function(){return i}});var r=n(7294);let i=(0,r.createContext)({user:null,username:null})},8233:function(e,t,n){"use strict";n.d(t,{mC:function(){return tq},I8:function(){return tP},RZ:function(){return tM},Lg:function(){return tF},qV:function(){return tL},Bt:function(){return tV},tO:function(){return tU}});var r,i,s,a,o=n(4444),l=n(8463),u=n(5816),c=n(3333);/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class h{constructor(e,t){this._delegate=e,this.firebase=t,(0,u._addComponent)(e,new l.wA("app-compat",()=>this,"PUBLIC")),this.container=e.container}get automaticDataCollectionEnabled(){return this._delegate.automaticDataCollectionEnabled}set automaticDataCollectionEnabled(e){this._delegate.automaticDataCollectionEnabled=e}get name(){return this._delegate.name}get options(){return this._delegate.options}delete(){return new Promise(e=>{this._delegate.checkDestroyed(),e()}).then(()=>(this.firebase.INTERNAL.removeApp(this.name),(0,u.deleteApp)(this._delegate)))}_getService(e,t=u._DEFAULT_ENTRY_NAME){var n;this._delegate.checkDestroyed();let r=this._delegate.container.getProvider(e);return r.isInitialized()||(null===(n=r.getComponent())||void 0===n?void 0:n.instantiationMode)!=="EXPLICIT"||r.initialize(),r.getImmediate({identifier:t})}_removeServiceInstance(e,t=u._DEFAULT_ENTRY_NAME){this._delegate.container.getProvider(e).clearInstance(t)}_addComponent(e){(0,u._addComponent)(this._delegate,e)}_addOrOverwriteComponent(e){(0,u._addOrOverwriteComponent)(this._delegate,e)}toJSON(){return{name:this.name,automaticDataCollectionEnabled:this.automaticDataCollectionEnabled,options:this.options}}}let d=new o.LL("app-compat","Firebase",{"no-app":"No Firebase App '{$appName}' has been created - call Firebase App.initializeApp()","invalid-app-argument":"firebase.{$appName}() takes either no argument or a Firebase App instance."}),f=/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function e(){let t=/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){let t={},n={__esModule:!0,initializeApp:function(r,i={}){let s=u.initializeApp(r,i);if((0,o.r3)(t,s.name))return t[s.name];let a=new e(s,n);return t[s.name]=a,a},app:r,registerVersion:u.registerVersion,setLogLevel:u.setLogLevel,onLog:u.onLog,apps:null,SDK_VERSION:u.SDK_VERSION,INTERNAL:{registerComponent:function(t){let i=t.name,s=i.replace("-compat","");if(u._registerComponent(t)&&"PUBLIC"===t.type){let a=(e=r())=>{if("function"!=typeof e[s])throw d.create("invalid-app-argument",{appName:i});return e[s]()};void 0!==t.serviceProps&&(0,o.ZB)(a,t.serviceProps),n[s]=a,e.prototype[s]=function(...e){let n=this._getService.bind(this,i);return n.apply(this,t.multipleInstances?e:[])}}return"PUBLIC"===t.type?n[s]:null},removeApp:function(e){delete t[e]},useAsService:function(e,t){return"serverAuth"===t?null:t},modularAPIs:u}};function r(e){if(e=e||u._DEFAULT_ENTRY_NAME,!(0,o.r3)(t,e))throw d.create("no-app",{appName:e});return t[e]}return n.default=n,Object.defineProperty(n,"apps",{get:function(){return Object.keys(t).map(e=>t[e])}}),r.App=e,n}(h);return t.INTERNAL=Object.assign(Object.assign({},t.INTERNAL),{createFirebaseNamespace:e,extendNamespace:function(e){(0,o.ZB)(t,e)},createSubscribe:o.ne,ErrorFactory:o.LL,deepExtend:o.ZB}),t}(),p=new c.Yd("@firebase/app-compat");/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */if((0,o.jU)()&&void 0!==self.firebase){p.warn(`
    Warning: Firebase is already defined in the global scope. Please make sure
    Firebase library is only loaded once.
  `);let e=self.firebase.SDK_VERSION;e&&e.indexOf("LITE")>=0&&p.warn(`
    Warning: You are trying to load Firebase while using Firebase Performance standalone script.
    You should load Firebase Performance with this instance of Firebase to avoid loading duplicate code.
    `)}(0,u.registerVersion)("@firebase/app-compat","0.2.3",void 0),/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */f.registerVersion("firebase","9.17.1","app-compat");var m=n(2191);/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function g(){return window}async function y(e,t,n){var r;let{BuildInfo:i}=g();(0,m.ap)(t.sessionId,"AuthEvent did not contain a session ID");let s=await _(t.sessionId),a={};return(0,m.aq)()?a.ibi=i.packageName:(0,m.ar)()?a.apn=i.packageName:(0,m.as)(e,"operation-not-supported-in-this-environment"),i.displayName&&(a.appDisplayName=i.displayName),a.sessionId=s,(0,m.at)(e,n,t.type,void 0,null!==(r=t.eventId)&&void 0!==r?r:void 0,a)}async function v(e){let{BuildInfo:t}=g(),n={};(0,m.aq)()?n.iosBundleId=t.packageName:(0,m.ar)()?n.androidPackageName=t.packageName:(0,m.as)(e,"operation-not-supported-in-this-environment"),await (0,m.au)(e,n)}async function w(e,t,n){let{cordova:r}=g(),i=()=>{};try{await new Promise((s,a)=>{let o=null;function l(){var e;s();let t=null===(e=r.plugins.browsertab)||void 0===e?void 0:e.close;"function"==typeof t&&t(),"function"==typeof(null==n?void 0:n.close)&&n.close()}function u(){o||(o=window.setTimeout(()=>{a((0,m.aw)(e,"redirect-cancelled-by-user"))},2e3))}function c(){(null==document?void 0:document.visibilityState)==="visible"&&u()}t.addPassiveListener(l),document.addEventListener("resume",u,!1),(0,m.ar)()&&document.addEventListener("visibilitychange",c,!1),i=()=>{t.removePassiveListener(l),document.removeEventListener("resume",u,!1),document.removeEventListener("visibilitychange",c,!1),o&&window.clearTimeout(o)}})}finally{i()}}async function _(e){let t=function(e){if((0,m.ap)(/[0-9a-zA-Z]+/.test(e),"Can only convert alpha-numeric strings"),"undefined"!=typeof TextEncoder)return new TextEncoder().encode(e);let t=new ArrayBuffer(e.length),n=new Uint8Array(t);for(let t=0;t<e.length;t++)n[t]=e.charCodeAt(t);return n}(e),n=await crypto.subtle.digest("SHA-256",t),r=Array.from(new Uint8Array(n));return r.map(e=>e.toString(16).padStart(2,"0")).join("")}class b extends m.ay{constructor(){super(...arguments),this.passiveListeners=new Set,this.initPromise=new Promise(e=>{this.resolveInialized=e})}addPassiveListener(e){this.passiveListeners.add(e)}removePassiveListener(e){this.passiveListeners.delete(e)}resetRedirect(){this.queuedRedirectEvent=null,this.hasHandledPotentialRedirect=!1}onEvent(e){return this.resolveInialized(),this.passiveListeners.forEach(t=>t(e)),super.onEvent(e)}async initialized(){await this.initPromise}}async function I(e){let t=await T()._get(E(e));return t&&await T()._remove(E(e)),t}function T(){return(0,m.az)(m.b)}function E(e){return(0,m.aA)("authEvent",e.config.apiKey,e.name)}function S(e){if(!(null==e?void 0:e.includes("?")))return{};let[t,...n]=e.split("?");return(0,o.zd)(n.join("?"))}let k=class{constructor(){this._redirectPersistence=m.a,this._shouldInitProactively=!0,this.eventManagers=new Map,this.originValidationPromises={},this._completeRedirectFn=m.aB,this._overrideRedirectResult=m.aC}async _initialize(e){let t=e._key(),n=this.eventManagers.get(t);return n||(n=new b(e),this.eventManagers.set(t,n),this.attachCallbackListeners(e,n)),n}_openPopup(e){(0,m.as)(e,"operation-not-supported-in-this-environment")}async _openRedirect(e,t,n,r){!function(e){var t,n,r,i,s,a,o,l,u,c;let h=g();(0,m.ax)("function"==typeof(null===(t=null==h?void 0:h.universalLinks)||void 0===t?void 0:t.subscribe),e,"invalid-cordova-configuration",{missingPlugin:"cordova-universal-links-plugin-fix"}),(0,m.ax)(void 0!==(null===(n=null==h?void 0:h.BuildInfo)||void 0===n?void 0:n.packageName),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-buildInfo"}),(0,m.ax)("function"==typeof(null===(s=null===(i=null===(r=null==h?void 0:h.cordova)||void 0===r?void 0:r.plugins)||void 0===i?void 0:i.browsertab)||void 0===s?void 0:s.openUrl),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-browsertab"}),(0,m.ax)("function"==typeof(null===(l=null===(o=null===(a=null==h?void 0:h.cordova)||void 0===a?void 0:a.plugins)||void 0===o?void 0:o.browsertab)||void 0===l?void 0:l.isAvailable),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-browsertab"}),(0,m.ax)("function"==typeof(null===(c=null===(u=null==h?void 0:h.cordova)||void 0===u?void 0:u.InAppBrowser)||void 0===c?void 0:c.open),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-inappbrowser"})}(e);let i=await this._initialize(e);await i.initialized(),i.resetRedirect(),(0,m.aD)(),await this._originValidation(e);let s=function(e,t,n=null){return{type:t,eventId:n,urlResponse:null,sessionId:function(){let e=[],t="1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";for(let n=0;n<20;n++){let n=Math.floor(Math.random()*t.length);e.push(t.charAt(n))}return e.join("")}(),postBody:null,tenantId:e.tenantId,error:(0,m.aw)(e,"no-auth-event")}}(e,n,r);await T()._set(E(e),s);let a=await y(e,s,t),o=await function(e){let{cordova:t}=g();return new Promise(n=>{t.plugins.browsertab.isAvailable(r=>{let i=null;r?t.plugins.browsertab.openUrl(e):i=t.InAppBrowser.open(e,(0,m.av)()?"_blank":"_system","location=yes"),n(i)})})}(a);return w(e,i,o)}_isIframeWebStorageSupported(e,t){throw Error("Method not implemented.")}_originValidation(e){let t=e._key();return this.originValidationPromises[t]||(this.originValidationPromises[t]=v(e)),this.originValidationPromises[t]}attachCallbackListeners(e,t){let{universalLinks:n,handleOpenURL:r,BuildInfo:i}=g(),s=setTimeout(async()=>{await I(e),t.onEvent(A())},500),a=async n=>{clearTimeout(s);let r=await I(e),i=null;r&&(null==n?void 0:n.url)&&(i=function(e,t){var n,r;let i=function(e){let t=S(e),n=t.link?decodeURIComponent(t.link):void 0,r=S(n).link,i=t.deep_link_id?decodeURIComponent(t.deep_link_id):void 0,s=S(i).link;return s||i||r||n||e}(t);if(i.includes("/__/auth/callback")){let t=S(i),s=t.firebaseError?function(e){try{return JSON.parse(e)}catch(e){return null}}(decodeURIComponent(t.firebaseError)):null,a=null===(r=null===(n=null==s?void 0:s.code)||void 0===n?void 0:n.split("auth/"))||void 0===r?void 0:r[1],o=a?(0,m.aw)(a):null;return o?{type:e.type,eventId:e.eventId,tenantId:e.tenantId,error:o,urlResponse:null,sessionId:null,postBody:null}:{type:e.type,eventId:e.eventId,tenantId:e.tenantId,sessionId:e.sessionId,urlResponse:i,postBody:null}}return null}(r,n.url)),t.onEvent(i||A())};void 0!==n&&"function"==typeof n.subscribe&&n.subscribe(null,a);let o=`${i.packageName.toLowerCase()}://`;g().handleOpenURL=async e=>{if(e.toLowerCase().startsWith(o)&&a({url:e}),"function"==typeof r)try{r(e)}catch(e){console.error(e)}}}};function A(){return{type:"unknown",eventId:null,sessionId:null,urlResponse:null,postBody:null,tenantId:null,error:(0,m.aw)("no-auth-event")}}function C(){var e;return(null===(e=null==self?void 0:self.location)||void 0===e?void 0:e.protocol)||null}function x(e=(0,o.z$)()){return!!(("file:"===C()||"ionic:"===C()||"capacitor:"===C())&&e.toLowerCase().match(/iphone|ipad|ipod|android/))}function N(){try{let e=self.localStorage,t=m.aI();if(e){if(e.setItem(t,"1"),e.removeItem(t),function(e=(0,o.z$)()){return(0,o.w1)()&&(null==document?void 0:document.documentMode)===11||function(e=(0,o.z$)()){return/Edge\/\d+/.test(e)}(e)}())return(0,o.hl)();return!0}}catch(e){return R()&&(0,o.hl)()}return!1}function R(){return void 0!==n.g&&"WorkerGlobalScope"in n.g&&"importScripts"in n.g}function D(){return("http:"===C()||"https:"===C()||(0,o.ru)()||x())&&!((0,o.b$)()||(0,o.UG)())&&N()&&!R()}function O(){return x()&&"undefined"!=typeof document}async function P(){return!!O()&&new Promise(e=>{let t=setTimeout(()=>{e(!1)},1e3);document.addEventListener("deviceready",()=>{clearTimeout(t),e(!0)})})}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let L={LOCAL:"local",NONE:"none",SESSION:"session"},M=m.ax,U="persistence";async function F(e){await e._initializationPromise;let t=V(),n=m.aA(U,e.config.apiKey,e.name);t&&t.setItem(n,e._getPersistence())}function V(){var e;try{return(null===(e="undefined"!=typeof window?window:null)||void 0===e?void 0:e.sessionStorage)||null}catch(e){return null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let q=m.ax;class B{constructor(){this.browserResolver=m.az(m.k),this.cordovaResolver=m.az(k),this.underlyingResolver=null,this._redirectPersistence=m.a,this._completeRedirectFn=m.aB,this._overrideRedirectResult=m.aC}async _initialize(e){return await this.selectUnderlyingResolver(),this.assertedUnderlyingResolver._initialize(e)}async _openPopup(e,t,n,r){return await this.selectUnderlyingResolver(),this.assertedUnderlyingResolver._openPopup(e,t,n,r)}async _openRedirect(e,t,n,r){return await this.selectUnderlyingResolver(),this.assertedUnderlyingResolver._openRedirect(e,t,n,r)}_isIframeWebStorageSupported(e,t){this.assertedUnderlyingResolver._isIframeWebStorageSupported(e,t)}_originValidation(e){return this.assertedUnderlyingResolver._originValidation(e)}get _shouldInitProactively(){return O()||this.browserResolver._shouldInitProactively}get assertedUnderlyingResolver(){return q(this.underlyingResolver,"internal-error"),this.underlyingResolver}async selectUnderlyingResolver(){if(this.underlyingResolver)return;let e=await P();this.underlyingResolver=e?this.cordovaResolver:this.browserResolver}}function j(e){let t;let{_tokenResponse:n}=e instanceof o.ZR?e.customData:e;if(!n)return null;if(!(e instanceof o.ZR)&&"temporaryProof"in n&&"phoneNumber"in n)return m.P.credentialFromResult(e);let r=n.providerId;if(!r||r===m.o.PASSWORD)return null;switch(r){case m.o.GOOGLE:t=m.Q;break;case m.o.FACEBOOK:t=m.N;break;case m.o.GITHUB:t=m.T;break;case m.o.TWITTER:t=m.W;break;default:let{oauthIdToken:i,oauthAccessToken:s,oauthTokenSecret:a,pendingToken:l,nonce:u}=n;if(!s&&!a&&!i&&!l)return null;if(l){if(r.startsWith("saml."))return m.aL._create(r,l);return m.J._fromParams({providerId:r,signInMethod:r,pendingToken:l,idToken:i,accessToken:s})}return new m.U(r).credential({idToken:i,accessToken:s,rawNonce:u})}return e instanceof o.ZR?t.credentialFromError(e):t.credentialFromResult(e)}function z(e,t){return t.catch(t=>{throw t instanceof o.ZR&&function(e,t){var n;let r=null===(n=t.customData)||void 0===n?void 0:n._tokenResponse;if((null==t?void 0:t.code)==="auth/multi-factor-auth-required"){let n=t;n.resolver=new G(e,m.an(e,t))}else if(r){let e=j(t),n=t;e&&(n.credential=e,n.tenantId=r.tenantId||void 0,n.email=r.email||void 0,n.phoneNumber=r.phoneNumber||void 0)}}(e,t),t}).then(e=>{let t=e.operationType,n=e.user;return{operationType:t,credential:j(e),additionalUserInfo:m.al(e),user:K.getOrCreate(n)}})}async function $(e,t){let n=await t;return{verificationId:n.verificationId,confirm:t=>z(e,n.confirm(t))}}class G{constructor(e,t){this.resolver=t,this.auth=e.wrapped()}get session(){return this.resolver.session}get hints(){return this.resolver.hints}resolveSignIn(e){return z(this.auth.unwrap(),this.resolver.resolveSignIn(e))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class K{constructor(e){this._delegate=e,this.multiFactor=m.ao(e)}static getOrCreate(e){return K.USER_MAP.has(e)||K.USER_MAP.set(e,new K(e)),K.USER_MAP.get(e)}delete(){return this._delegate.delete()}reload(){return this._delegate.reload()}toJSON(){return this._delegate.toJSON()}getIdTokenResult(e){return this._delegate.getIdTokenResult(e)}getIdToken(e){return this._delegate.getIdToken(e)}linkAndRetrieveDataWithCredential(e){return this.linkWithCredential(e)}async linkWithCredential(e){return z(this.auth,m.Z(this._delegate,e))}async linkWithPhoneNumber(e,t){return $(this.auth,m.l(this._delegate,e,t))}async linkWithPopup(e){return z(this.auth,m.d(this._delegate,e,B))}async linkWithRedirect(e){return await F(m.aE(this.auth)),m.g(this._delegate,e,B)}reauthenticateAndRetrieveDataWithCredential(e){return this.reauthenticateWithCredential(e)}async reauthenticateWithCredential(e){return z(this.auth,m._(this._delegate,e))}reauthenticateWithPhoneNumber(e,t){return $(this.auth,m.r(this._delegate,e,t))}reauthenticateWithPopup(e){return z(this.auth,m.e(this._delegate,e,B))}async reauthenticateWithRedirect(e){return await F(m.aE(this.auth)),m.h(this._delegate,e,B)}sendEmailVerification(e){return m.ab(this._delegate,e)}async unlink(e){return await m.ak(this._delegate,e),this}updateEmail(e){return m.ag(this._delegate,e)}updatePassword(e){return m.ah(this._delegate,e)}updatePhoneNumber(e){return m.u(this._delegate,e)}updateProfile(e){return m.af(this._delegate,e)}verifyBeforeUpdateEmail(e,t){return m.ac(this._delegate,e,t)}get emailVerified(){return this._delegate.emailVerified}get isAnonymous(){return this._delegate.isAnonymous}get metadata(){return this._delegate.metadata}get phoneNumber(){return this._delegate.phoneNumber}get providerData(){return this._delegate.providerData}get refreshToken(){return this._delegate.refreshToken}get tenantId(){return this._delegate.tenantId}get displayName(){return this._delegate.displayName}get email(){return this._delegate.email}get photoURL(){return this._delegate.photoURL}get providerId(){return this._delegate.providerId}get uid(){return this._delegate.uid}get auth(){return this._delegate.auth}}K.USER_MAP=new WeakMap;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let W=m.ax;class H{constructor(e,t){if(this.app=e,t.isInitialized()){this._delegate=t.getImmediate(),this.linkUnderlyingAuth();return}let{apiKey:n}=e.options;W(n,"invalid-api-key",{appName:e.name}),W(n,"invalid-api-key",{appName:e.name});let r="undefined"!=typeof window?B:void 0;this._delegate=t.initialize({options:{persistence:function(e,t){let n=function(e,t){let n=V();if(!n)return[];let r=m.aA(U,e,t),i=n.getItem(r);switch(i){case L.NONE:return[m.L];case L.LOCAL:return[m.i,m.a];case L.SESSION:return[m.a];default:return[]}}(e,t);if("undefined"==typeof self||n.includes(m.i)||n.push(m.i),"undefined"!=typeof window)for(let e of[m.b,m.a])n.includes(e)||n.push(e);return n.includes(m.L)||n.push(m.L),n}(n,e.name),popupRedirectResolver:r}}),this._delegate._updateErrorMap(m.B),this.linkUnderlyingAuth()}get emulatorConfig(){return this._delegate.emulatorConfig}get currentUser(){return this._delegate.currentUser?K.getOrCreate(this._delegate.currentUser):null}get languageCode(){return this._delegate.languageCode}set languageCode(e){this._delegate.languageCode=e}get settings(){return this._delegate.settings}get tenantId(){return this._delegate.tenantId}set tenantId(e){this._delegate.tenantId=e}useDeviceLanguage(){this._delegate.useDeviceLanguage()}signOut(){return this._delegate.signOut()}useEmulator(e,t){m.G(this._delegate,e,t)}applyActionCode(e){return m.a2(this._delegate,e)}checkActionCode(e){return m.a3(this._delegate,e)}confirmPasswordReset(e,t){return m.a1(this._delegate,e,t)}async createUserWithEmailAndPassword(e,t){return z(this._delegate,m.a5(this._delegate,e,t))}fetchProvidersForEmail(e){return this.fetchSignInMethodsForEmail(e)}fetchSignInMethodsForEmail(e){return m.aa(this._delegate,e)}isSignInWithEmailLink(e){return m.a8(this._delegate,e)}async getRedirectResult(){W(D(),this._delegate,"operation-not-supported-in-this-environment");let e=await m.j(this._delegate,B);return e?z(this._delegate,Promise.resolve(e)):{credential:null,user:null}}addFrameworkForLogging(e){!/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e,t){(0,m.aE)(e)._logFramework(t)}(this._delegate,e)}onAuthStateChanged(e,t,n){let{next:r,error:i,complete:s}=Q(e,t,n);return this._delegate.onAuthStateChanged(r,i,s)}onIdTokenChanged(e,t,n){let{next:r,error:i,complete:s}=Q(e,t,n);return this._delegate.onIdTokenChanged(r,i,s)}sendSignInLinkToEmail(e,t){return m.a7(this._delegate,e,t)}sendPasswordResetEmail(e,t){return m.a0(this._delegate,e,t||void 0)}async setPersistence(e){let t;switch(!function(e,t){if(M(Object.values(L).includes(t),e,"invalid-persistence-type"),(0,o.b$)()){M(t!==L.SESSION,e,"unsupported-persistence-type");return}if((0,o.UG)()){M(t===L.NONE,e,"unsupported-persistence-type");return}if(R()){M(t===L.NONE||t===L.LOCAL&&(0,o.hl)(),e,"unsupported-persistence-type");return}M(t===L.NONE||N(),e,"unsupported-persistence-type")}(this._delegate,e),e){case L.SESSION:t=m.a;break;case L.LOCAL:let n=await m.az(m.i)._isAvailable();t=n?m.i:m.b;break;case L.NONE:t=m.L;break;default:return m.as("argument-error",{appName:this._delegate.name})}return this._delegate.setPersistence(t)}signInAndRetrieveDataWithCredential(e){return this.signInWithCredential(e)}signInAnonymously(){return z(this._delegate,m.X(this._delegate))}signInWithCredential(e){return z(this._delegate,m.Y(this._delegate,e))}signInWithCustomToken(e){return z(this._delegate,m.$(this._delegate,e))}signInWithEmailAndPassword(e,t){return z(this._delegate,m.a6(this._delegate,e,t))}signInWithEmailLink(e,t){return z(this._delegate,m.a9(this._delegate,e,t))}signInWithPhoneNumber(e,t){return $(this._delegate,m.s(this._delegate,e,t))}async signInWithPopup(e){return W(D(),this._delegate,"operation-not-supported-in-this-environment"),z(this._delegate,m.c(this._delegate,e,B))}async signInWithRedirect(e){return W(D(),this._delegate,"operation-not-supported-in-this-environment"),await F(this._delegate),m.f(this._delegate,e,B)}updateCurrentUser(e){return this._delegate.updateCurrentUser(e)}verifyPasswordResetCode(e){return m.a4(this._delegate,e)}unwrap(){return this._delegate}_delete(){return this._delegate._delete()}linkUnderlyingAuth(){this._delegate.wrapped=()=>this}}function Q(e,t,n){let r=e;"function"!=typeof e&&({next:r,error:t,complete:n}=e);let i=r,s=e=>i(e&&K.getOrCreate(e));return{next:s,error:t,complete:n}}H.Persistence=L;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class Y{constructor(){this.providerId="phone",this._delegate=new m.P(f.auth().unwrap())}static credential(e,t){return m.P.credential(e,t)}verifyPhoneNumber(e,t){return this._delegate.verifyPhoneNumber(e,t)}unwrap(){return this._delegate}}Y.PHONE_SIGN_IN_METHOD=m.P.PHONE_SIGN_IN_METHOD,Y.PROVIDER_ID=m.P.PROVIDER_ID;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let X=m.ax;f.INTERNAL.registerComponent(new l.wA("auth-compat",e=>{let t=e.getProvider("app-compat").getImmediate(),n=e.getProvider("auth");return new H(t,n)},"PUBLIC").setServiceProps({ActionCodeInfo:{Operation:{EMAIL_SIGNIN:m.A.EMAIL_SIGNIN,PASSWORD_RESET:m.A.PASSWORD_RESET,RECOVER_EMAIL:m.A.RECOVER_EMAIL,REVERT_SECOND_FACTOR_ADDITION:m.A.REVERT_SECOND_FACTOR_ADDITION,VERIFY_AND_CHANGE_EMAIL:m.A.VERIFY_AND_CHANGE_EMAIL,VERIFY_EMAIL:m.A.VERIFY_EMAIL}},EmailAuthProvider:m.M,FacebookAuthProvider:m.N,GithubAuthProvider:m.T,GoogleAuthProvider:m.Q,OAuthProvider:m.U,SAMLAuthProvider:m.V,PhoneAuthProvider:Y,PhoneMultiFactorGenerator:m.m,RecaptchaVerifier:class{constructor(e,t,n=f.app()){var r;X(null===(r=n.options)||void 0===r?void 0:r.apiKey,"invalid-api-key",{appName:n.name}),this._delegate=new m.R(e,t,n.auth()),this.type=this._delegate.type}clear(){this._delegate.clear()}render(){return this._delegate.render()}verify(){return this._delegate.verify()}},TwitterAuthProvider:m.W,Auth:H,AuthCredential:m.H,Error:o.ZR}).setInstantiationMode("LAZY").setMultipleInstances(!1)),f.registerVersion("@firebase/auth-compat","0.3.3");var J=n(1294);/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function Z(e,t){if(void 0===t)return{merge:!1};if(void 0!==t.mergeFields&&void 0!==t.merge)throw new J.WA("invalid-argument",`Invalid options passed to function ${e}(): You cannot specify both "merge" and "mergeFields".`);return t}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ee(){if("undefined"==typeof Uint8Array)throw new J.WA("unimplemented","Uint8Arrays are not available in this environment.")}function et(){if(!(0,J.Me)())throw new J.WA("unimplemented","Blobs are unavailable in Firestore in this environment.")}class en{constructor(e){this._delegate=e}static fromBase64String(e){return et(),new en(J.Jj.fromBase64String(e))}static fromUint8Array(e){return ee(),new en(J.Jj.fromUint8Array(e))}toBase64(){return et(),this._delegate.toBase64()}toUint8Array(){return ee(),this._delegate.toUint8Array()}isEqual(e){return this._delegate.isEqual(e._delegate)}toString(){return"Blob(base64: "+this.toBase64()+")"}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function er(e){return function(e,t){if("object"!=typeof e||null===e)return!1;for(let n of t)if(n in e&&"function"==typeof e[n])return!0;return!1}(e,["next","error","complete"])}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ei{enableIndexedDbPersistence(e,t){return(0,J.ST)(e._delegate,{forceOwnership:t})}enableMultiTabIndexedDbPersistence(e){return(0,J.fH)(e._delegate)}clearIndexedDbPersistence(e){return(0,J.Fc)(e._delegate)}}class es{constructor(e,t,n){this._delegate=t,this._persistenceProvider=n,this.INTERNAL={delete:()=>this.terminate()},e instanceof J.l7||(this._appCompat=e)}get _databaseId(){return this._delegate._databaseId}settings(e){let t=this._delegate._getSettings();e.merge||t.host===e.host||(0,J.yq)("You are overriding the original host. If you did not intend to override your settings, use {merge: true}."),e.merge&&delete(e=Object.assign(Object.assign({},t),e)).merge,this._delegate._setSettings(e)}useEmulator(e,t,n={}){(0,J.at)(this._delegate,e,t,n)}enableNetwork(){return(0,J.Ix)(this._delegate)}disableNetwork(){return(0,J.TF)(this._delegate)}enablePersistence(e){let t=!1,n=!1;return e&&(t=!!e.synchronizeTabs,n=!!e.experimentalForceOwningTab,(0,J.Wi)("synchronizeTabs",t,"experimentalForceOwningTab",n)),t?this._persistenceProvider.enableMultiTabIndexedDbPersistence(this):this._persistenceProvider.enableIndexedDbPersistence(this,n)}clearPersistence(){return this._persistenceProvider.clearIndexedDbPersistence(this)}terminate(){return this._appCompat&&(this._appCompat._removeServiceInstance("firestore-compat"),this._appCompat._removeServiceInstance("firestore")),this._delegate._delete()}waitForPendingWrites(){return(0,J.Mx)(this._delegate)}onSnapshotsInSync(e){return(0,J.sc)(this._delegate,e)}get app(){if(!this._appCompat)throw new J.WA("failed-precondition","Firestore was not initialized using the Firebase SDK. 'app' is not available");return this._appCompat}collection(e){try{return new ew(this,(0,J.hJ)(this._delegate,e))}catch(e){throw eh(e,"collection()","Firestore.collection()")}}doc(e){try{return new ec(this,(0,J.JU)(this._delegate,e))}catch(e){throw eh(e,"doc()","Firestore.doc()")}}collectionGroup(e){try{return new eg(this,(0,J.B$)(this._delegate,e))}catch(e){throw eh(e,"collectionGroup()","Firestore.collectionGroup()")}}runTransaction(e){return(0,J.i3)(this._delegate,t=>e(new eo(this,t)))}batch(){return(0,J.qY)(this._delegate),new el(new J.PU(this._delegate,e=>(0,J.GL)(this._delegate,e)))}loadBundle(e){return(0,J.Pb)(this._delegate,e)}namedQuery(e){return(0,J.L$)(this._delegate,e).then(e=>e?new eg(this,e):null)}}class ea extends J.u7{constructor(e){super(),this.firestore=e}convertBytes(e){return new en(new J.Jj(e))}convertReference(e){let t=this.convertDocumentKey(e,this.firestore._databaseId);return ec.forKey(t,this.firestore,null)}}class eo{constructor(e,t){this._firestore=e,this._delegate=t,this._userDataWriter=new ea(e)}get(e){let t=e_(e);return this._delegate.get(t).then(e=>new ep(this._firestore,new J.xU(this._firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,t.converter)))}set(e,t,n){let r=e_(e);return n?(Z("Transaction.set",n),this._delegate.set(r,t,n)):this._delegate.set(r,t),this}update(e,t,n,...r){let i=e_(e);return 2==arguments.length?this._delegate.update(i,t):this._delegate.update(i,t,n,...r),this}delete(e){let t=e_(e);return this._delegate.delete(t),this}}class el{constructor(e){this._delegate=e}set(e,t,n){let r=e_(e);return n?(Z("WriteBatch.set",n),this._delegate.set(r,t,n)):this._delegate.set(r,t),this}update(e,t,n,...r){let i=e_(e);return 2==arguments.length?this._delegate.update(i,t):this._delegate.update(i,t,n,...r),this}delete(e){let t=e_(e);return this._delegate.delete(t),this}commit(){return this._delegate.commit()}}class eu{constructor(e,t,n){this._firestore=e,this._userDataWriter=t,this._delegate=n}fromFirestore(e,t){let n=new J.$q(this._firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,null);return this._delegate.fromFirestore(new em(this._firestore,n),null!=t?t:{})}toFirestore(e,t){return t?this._delegate.toFirestore(e,t):this._delegate.toFirestore(e)}static getInstance(e,t){let n=eu.INSTANCES,r=n.get(e);r||(r=new WeakMap,n.set(e,r));let i=r.get(t);return i||(i=new eu(e,new ea(e),t),r.set(t,i)),i}}eu.INSTANCES=new WeakMap;class ec{constructor(e,t){this.firestore=e,this._delegate=t,this._userDataWriter=new ea(e)}static forPath(e,t,n){if(e.length%2!=0)throw new J.WA("invalid-argument",`Invalid document reference. Document references must have an even number of segments, but ${e.canonicalString()} has ${e.length}`);return new ec(t,new J.my(t._delegate,n,new J.Ky(e)))}static forKey(e,t,n){return new ec(t,new J.my(t._delegate,n,e))}get id(){return this._delegate.id}get parent(){return new ew(this.firestore,this._delegate.parent)}get path(){return this._delegate.path}collection(e){try{return new ew(this.firestore,(0,J.hJ)(this._delegate,e))}catch(e){throw eh(e,"collection()","DocumentReference.collection()")}}isEqual(e){return(e=(0,o.m9)(e))instanceof J.my&&(0,J.Eo)(this._delegate,e)}set(e,t){t=Z("DocumentReference.set",t);try{if(t)return(0,J.pl)(this._delegate,e,t);return(0,J.pl)(this._delegate,e)}catch(e){throw eh(e,"setDoc()","DocumentReference.set()")}}update(e,t,...n){try{if(1==arguments.length)return(0,J.r7)(this._delegate,e);return(0,J.r7)(this._delegate,e,t,...n)}catch(e){throw eh(e,"updateDoc()","DocumentReference.update()")}}delete(){return(0,J.oe)(this._delegate)}onSnapshot(...e){let t=ed(e),n=ef(e,e=>new ep(this.firestore,new J.xU(this.firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,this._delegate.converter)));return(0,J.cf)(this._delegate,t,n)}get(e){return((null==e?void 0:e.source)==="cache"?(0,J.kl)(this._delegate):(null==e?void 0:e.source)==="server"?(0,J.Xk)(this._delegate):(0,J.QT)(this._delegate)).then(e=>new ep(this.firestore,new J.xU(this.firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,this._delegate.converter)))}withConverter(e){return new ec(this.firestore,e?this._delegate.withConverter(eu.getInstance(this.firestore,e)):this._delegate.withConverter(null))}}function eh(e,t,n){return e.message=e.message.replace(t,n),e}function ed(e){for(let t of e)if("object"==typeof t&&!er(t))return t;return{}}function ef(e,t){var n,r;let i;return{next:e=>{i.next&&i.next(t(e))},error:null===(n=(i=er(e[0])?e[0]:er(e[1])?e[1]:"function"==typeof e[0]?{next:e[0],error:e[1],complete:e[2]}:{next:e[1],error:e[2],complete:e[3]}).error)||void 0===n?void 0:n.bind(i),complete:null===(r=i.complete)||void 0===r?void 0:r.bind(i)}}class ep{constructor(e,t){this._firestore=e,this._delegate=t}get ref(){return new ec(this._firestore,this._delegate.ref)}get id(){return this._delegate.id}get metadata(){return this._delegate.metadata}get exists(){return this._delegate.exists()}data(e){return this._delegate.data(e)}get(e,t){return this._delegate.get(e,t)}isEqual(e){return(0,J.qK)(this._delegate,e._delegate)}}class em extends ep{data(e){let t=this._delegate.data(e);return(0,J.K9)(void 0!==t,"Document in a QueryDocumentSnapshot should exist"),t}}class eg{constructor(e,t){this.firestore=e,this._delegate=t,this._userDataWriter=new ea(e)}where(e,t,n){try{return new eg(this.firestore,(0,J.IO)(this._delegate,(0,J.ar)(e,t,n)))}catch(e){throw eh(e,/(orderBy|where)\(\)/,"Query.$1()")}}orderBy(e,t){try{return new eg(this.firestore,(0,J.IO)(this._delegate,(0,J.Xo)(e,t)))}catch(e){throw eh(e,/(orderBy|where)\(\)/,"Query.$1()")}}limit(e){try{return new eg(this.firestore,(0,J.IO)(this._delegate,(0,J.b9)(e)))}catch(e){throw eh(e,"limit()","Query.limit()")}}limitToLast(e){try{return new eg(this.firestore,(0,J.IO)(this._delegate,(0,J.vh)(e)))}catch(e){throw eh(e,"limitToLast()","Query.limitToLast()")}}startAt(...e){try{return new eg(this.firestore,(0,J.IO)(this._delegate,(0,J.e0)(...e)))}catch(e){throw eh(e,"startAt()","Query.startAt()")}}startAfter(...e){try{return new eg(this.firestore,(0,J.IO)(this._delegate,(0,J.TQ)(...e)))}catch(e){throw eh(e,"startAfter()","Query.startAfter()")}}endBefore(...e){try{return new eg(this.firestore,(0,J.IO)(this._delegate,(0,J.Lx)(...e)))}catch(e){throw eh(e,"endBefore()","Query.endBefore()")}}endAt(...e){try{return new eg(this.firestore,(0,J.IO)(this._delegate,(0,J.Wu)(...e)))}catch(e){throw eh(e,"endAt()","Query.endAt()")}}isEqual(e){return(0,J.iE)(this._delegate,e._delegate)}get(e){return((null==e?void 0:e.source)==="cache"?(0,J.UQ)(this._delegate):(null==e?void 0:e.source)==="server"?(0,J.zN)(this._delegate):(0,J.PL)(this._delegate)).then(e=>new ev(this.firestore,new J.W(this.firestore._delegate,this._userDataWriter,this._delegate,e._snapshot)))}onSnapshot(...e){let t=ed(e),n=ef(e,e=>new ev(this.firestore,new J.W(this.firestore._delegate,this._userDataWriter,this._delegate,e._snapshot)));return(0,J.cf)(this._delegate,t,n)}withConverter(e){return new eg(this.firestore,e?this._delegate.withConverter(eu.getInstance(this.firestore,e)):this._delegate.withConverter(null))}}class ey{constructor(e,t){this._firestore=e,this._delegate=t}get type(){return this._delegate.type}get doc(){return new em(this._firestore,this._delegate.doc)}get oldIndex(){return this._delegate.oldIndex}get newIndex(){return this._delegate.newIndex}}class ev{constructor(e,t){this._firestore=e,this._delegate=t}get query(){return new eg(this._firestore,this._delegate.query)}get metadata(){return this._delegate.metadata}get size(){return this._delegate.size}get empty(){return this._delegate.empty}get docs(){return this._delegate.docs.map(e=>new em(this._firestore,e))}docChanges(e){return this._delegate.docChanges(e).map(e=>new ey(this._firestore,e))}forEach(e,t){this._delegate.forEach(n=>{e.call(t,new em(this._firestore,n))})}isEqual(e){return(0,J.qK)(this._delegate,e._delegate)}}class ew extends eg{constructor(e,t){super(e,t),this.firestore=e,this._delegate=t}get id(){return this._delegate.id}get path(){return this._delegate.path}get parent(){let e=this._delegate.parent;return e?new ec(this.firestore,e):null}doc(e){try{if(void 0===e)return new ec(this.firestore,(0,J.JU)(this._delegate));return new ec(this.firestore,(0,J.JU)(this._delegate,e))}catch(e){throw eh(e,"doc()","CollectionReference.doc()")}}add(e){return(0,J.ET)(this._delegate,e).then(e=>new ec(this.firestore,e))}isEqual(e){return(0,J.Eo)(this._delegate,e._delegate)}withConverter(e){return new ew(this.firestore,e?this._delegate.withConverter(eu.getInstance(this.firestore,e)):this._delegate.withConverter(null))}}function e_(e){return(0,J.Cf)(e,J.my)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eb{constructor(...e){this._delegate=new J.Lz(...e)}static documentId(){return new eb(J.Xb.keyField().canonicalString())}isEqual(e){return(e=(0,o.m9)(e))instanceof J.Lz&&this._delegate._internalPath.isEqual(e._internalPath)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eI{constructor(e){this._delegate=e}static serverTimestamp(){let e=(0,J.Bt)();return e._methodName="FieldValue.serverTimestamp",new eI(e)}static delete(){let e=(0,J.AK)();return e._methodName="FieldValue.delete",new eI(e)}static arrayUnion(...e){let t=(0,J.vr)(...e);return t._methodName="FieldValue.arrayUnion",new eI(t)}static arrayRemove(...e){let t=(0,J.Ab)(...e);return t._methodName="FieldValue.arrayRemove",new eI(t)}static increment(e){let t=(0,J.nP)(e);return t._methodName="FieldValue.increment",new eI(t)}isEqual(e){return this._delegate.isEqual(e._delegate)}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let eT={Firestore:es,GeoPoint:J.F8,Timestamp:J.EK,Blob:en,Transaction:eo,WriteBatch:el,DocumentReference:ec,DocumentSnapshot:ep,Query:eg,QueryDocumentSnapshot:em,QuerySnapshot:ev,CollectionReference:ew,FieldPath:eb,FieldValue:eI,setLogLevel:function(e){(0,J.Ub)(e)},CACHE_SIZE_UNLIMITED:J.IX};!function(e,t){e.INTERNAL.registerComponent(new l.wA("firestore-compat",e=>{let n=e.getProvider("app-compat").getImmediate(),r=e.getProvider("firestore").getImmediate();return t(n,r)},"PUBLIC").setServiceProps(Object.assign({},eT)))}(f,(e,t)=>new es(e,t,new ei)),f.registerVersion("@firebase/firestore-compat","0.3.3");/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let eE="firebasestorage.googleapis.com",eS="storageBucket";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ek extends o.ZR{constructor(e,t,n=0){super(eA(e),`Firebase Storage: ${t} (${eA(e)})`),this.status_=n,this.customData={serverResponse:null},this._baseMessage=this.message,Object.setPrototypeOf(this,ek.prototype)}get status(){return this.status_}set status(e){this.status_=e}_codeEquals(e){return eA(e)===this.code}get serverResponse(){return this.customData.serverResponse}set serverResponse(e){this.customData.serverResponse=e,this.customData.serverResponse?this.message=`${this._baseMessage}
${this.customData.serverResponse}`:this.message=this._baseMessage}}function eA(e){return"storage/"+e}function eC(){return new ek(s.UNKNOWN,"An unknown error occurred, please check the error payload for server response.")}function ex(){return new ek(s.RETRY_LIMIT_EXCEEDED,"Max retry time for operation exceeded, please try again.")}function eN(){return new ek(s.CANCELED,"User canceled the upload/download.")}function eR(){return new ek(s.CANNOT_SLICE_BLOB,"Cannot slice blob for upload. Please retry the upload.")}function eD(e){return new ek(s.INVALID_ARGUMENT,e)}function eO(){return new ek(s.APP_DELETED,"The Firebase app was deleted.")}function eP(e){return new ek(s.INVALID_ROOT_OPERATION,"The operation '"+e+"' cannot be performed on a root reference, create a non-root reference using child, such as .child('file.png').")}function eL(e,t){return new ek(s.INVALID_FORMAT,"String does not match format '"+e+"': "+t)}function eM(e){throw new ek(s.INTERNAL_ERROR,"Internal error: "+e)}(r=s||(s={})).UNKNOWN="unknown",r.OBJECT_NOT_FOUND="object-not-found",r.BUCKET_NOT_FOUND="bucket-not-found",r.PROJECT_NOT_FOUND="project-not-found",r.QUOTA_EXCEEDED="quota-exceeded",r.UNAUTHENTICATED="unauthenticated",r.UNAUTHORIZED="unauthorized",r.UNAUTHORIZED_APP="unauthorized-app",r.RETRY_LIMIT_EXCEEDED="retry-limit-exceeded",r.INVALID_CHECKSUM="invalid-checksum",r.CANCELED="canceled",r.INVALID_EVENT_NAME="invalid-event-name",r.INVALID_URL="invalid-url",r.INVALID_DEFAULT_BUCKET="invalid-default-bucket",r.NO_DEFAULT_BUCKET="no-default-bucket",r.CANNOT_SLICE_BLOB="cannot-slice-blob",r.SERVER_FILE_WRONG_SIZE="server-file-wrong-size",r.NO_DOWNLOAD_URL="no-download-url",r.INVALID_ARGUMENT="invalid-argument",r.INVALID_ARGUMENT_COUNT="invalid-argument-count",r.APP_DELETED="app-deleted",r.INVALID_ROOT_OPERATION="invalid-root-operation",r.INVALID_FORMAT="invalid-format",r.INTERNAL_ERROR="internal-error",r.UNSUPPORTED_ENVIRONMENT="unsupported-environment";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eU{constructor(e,t){this.bucket=e,this.path_=t}get path(){return this.path_}get isRoot(){return 0===this.path.length}fullServerUrl(){let e=encodeURIComponent;return"/b/"+e(this.bucket)+"/o/"+e(this.path)}bucketOnlyServerUrl(){let e=encodeURIComponent;return"/b/"+e(this.bucket)+"/o"}static makeFromBucketSpec(e,t){let n;try{n=eU.makeFromUrl(e,t)}catch(t){return new eU(e,"")}if(""===n.path)return n;throw new ek(s.INVALID_DEFAULT_BUCKET,"Invalid default bucket '"+e+"'.")}static makeFromUrl(e,t){let n=null,r="([A-Za-z0-9.\\-_]+)",i=RegExp("^gs://"+r+"(/(.*))?$","i");function a(e){e.path_=decodeURIComponent(e.path)}let o=t.replace(/[.]/g,"\\."),l=RegExp(`^https?://${o}/v[A-Za-z0-9_]+/b/${r}/o(/([^?#]*).*)?$`,"i"),u=RegExp(`^https?://${t===eE?"(?:storage.googleapis.com|storage.cloud.google.com)":t}/${r}/([^?#]*)`,"i"),c=[{regex:i,indices:{bucket:1,path:3},postModify:function(e){"/"===e.path.charAt(e.path.length-1)&&(e.path_=e.path_.slice(0,-1))}},{regex:l,indices:{bucket:1,path:3},postModify:a},{regex:u,indices:{bucket:1,path:2},postModify:a}];for(let t=0;t<c.length;t++){let r=c[t],i=r.regex.exec(e);if(i){let e=i[r.indices.bucket],t=i[r.indices.path];t||(t=""),n=new eU(e,t),r.postModify(n);break}}if(null==n)throw new ek(s.INVALID_URL,"Invalid URL '"+e+"'.");return n}}class eF{constructor(e){this.promise_=Promise.reject(e)}getPromise(){return this.promise_}cancel(e=!1){}}function eV(e){return"string"==typeof e||e instanceof String}function eq(e){return eB()&&e instanceof Blob}function eB(){return"undefined"!=typeof Blob&&!(0,o.UG)()}function ej(e,t,n,r){if(r<t)throw eD(`Invalid value for '${e}'. Expected ${t} or greater.`);if(r>n)throw eD(`Invalid value for '${e}'. Expected ${n} or less.`)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ez(e,t,n){let r=t;return null==n&&(r=`https://${t}`),`${n}://${r}/v0${e}`}function e$(e){let t=encodeURIComponent,n="?";for(let r in e)if(e.hasOwnProperty(r)){let i=t(r)+"="+t(e[r]);n=n+i+"&"}return n.slice(0,-1)}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function eG(e,t){let n=-1!==[408,429].indexOf(e),r=-1!==t.indexOf(e);return e>=500&&e<600||n||r}(i=a||(a={}))[i.NO_ERROR=0]="NO_ERROR",i[i.NETWORK_ERROR=1]="NETWORK_ERROR",i[i.ABORT=2]="ABORT";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eK{constructor(e,t,n,r,i,s,a,o,l,u,c,h=!0){this.url_=e,this.method_=t,this.headers_=n,this.body_=r,this.successCodes_=i,this.additionalRetryCodes_=s,this.callback_=a,this.errorCallback_=o,this.timeout_=l,this.progressCallback_=u,this.connectionFactory_=c,this.retry=h,this.pendingConnection_=null,this.backoffId_=null,this.canceled_=!1,this.appDelete_=!1,this.promise_=new Promise((e,t)=>{this.resolve_=e,this.reject_=t,this.start_()})}start_(){let e=(e,t)=>{if(t){e(!1,new eW(!1,null,!0));return}let n=this.connectionFactory_();this.pendingConnection_=n;let r=e=>{let t=e.loaded,n=e.lengthComputable?e.total:-1;null!==this.progressCallback_&&this.progressCallback_(t,n)};null!==this.progressCallback_&&n.addUploadProgressListener(r),n.send(this.url_,this.method_,this.body_,this.headers_).then(()=>{null!==this.progressCallback_&&n.removeUploadProgressListener(r),this.pendingConnection_=null;let t=n.getErrorCode()===a.NO_ERROR,i=n.getStatus();if(!t||eG(i,this.additionalRetryCodes_)&&this.retry){let t=n.getErrorCode()===a.ABORT;e(!1,new eW(!1,null,t));return}let s=-1!==this.successCodes_.indexOf(i);e(!0,new eW(s,n))})},t=(e,t)=>{let n=this.resolve_,r=this.reject_,i=t.connection;if(t.wasSuccessCode)try{let e=this.callback_(i,i.getResponse());void 0!==e?n(e):n()}catch(e){r(e)}else if(null!==i){let e=eC();e.serverResponse=i.getErrorText(),r(this.errorCallback_?this.errorCallback_(i,e):e)}else if(t.canceled){let e=this.appDelete_?eO():eN();r(e)}else{let e=ex();r(e)}};this.canceled_?t(!1,new eW(!1,null,!0)):this.backoffId_=/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e,t,n){let r=1,i=null,s=null,a=!1,o=0,l=!1;function u(...e){l||(l=!0,t.apply(null,e))}function c(t){i=setTimeout(()=>{i=null,e(d,2===o)},t)}function h(){s&&clearTimeout(s)}function d(e,...t){let n;if(l){h();return}if(e){h(),u.call(null,e,...t);return}let i=2===o||a;if(i){h(),u.call(null,e,...t);return}r<64&&(r*=2),1===o?(o=2,n=0):n=(r+Math.random())*1e3,c(n)}let f=!1;function p(e){!f&&(f=!0,h(),!l&&(null!==i?(e||(o=2),clearTimeout(i),c(0)):e||(o=1)))}return c(0),s=setTimeout(()=>{a=!0,p(!0)},n),p}(e,t,this.timeout_)}getPromise(){return this.promise_}cancel(e){this.canceled_=!0,this.appDelete_=e||!1,null!==this.backoffId_&&(0,this.backoffId_)(!1),null!==this.pendingConnection_&&this.pendingConnection_.abort()}}class eW{constructor(e,t,n){this.wasSuccessCode=e,this.connection=t,this.canceled=!!n}}function eH(...e){let t="undefined"!=typeof BlobBuilder?BlobBuilder:"undefined"!=typeof WebKitBlobBuilder?WebKitBlobBuilder:void 0;if(void 0!==t){let n=new t;for(let t=0;t<e.length;t++)n.append(e[t]);return n.getBlob()}if(eB())return new Blob(e);throw new ek(s.UNSUPPORTED_ENVIRONMENT,"This browser doesn't seem to support creating Blobs")}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let eQ={RAW:"raw",BASE64:"base64",BASE64URL:"base64url",DATA_URL:"data_url"};class eY{constructor(e,t){this.data=e,this.contentType=t||null}}function eX(e,t){switch(e){case eQ.RAW:return new eY(eJ(t));case eQ.BASE64:case eQ.BASE64URL:return new eY(eZ(e,t));case eQ.DATA_URL:return new eY(function(e){let t=new e0(e);return t.base64?eZ(eQ.BASE64,t.rest):function(e){let t;try{t=decodeURIComponent(e)}catch(e){throw eL(eQ.DATA_URL,"Malformed data URL.")}return eJ(t)}(t.rest)}(t),function(e){let t=new e0(e);return t.contentType}(t))}throw eC()}function eJ(e){let t=[];for(let n=0;n<e.length;n++){let r=e.charCodeAt(n);if(r<=127)t.push(r);else if(r<=2047)t.push(192|r>>6,128|63&r);else if((64512&r)==55296){let i=n<e.length-1&&(64512&e.charCodeAt(n+1))==56320;if(i){let i=r,s=e.charCodeAt(++n);r=65536|(1023&i)<<10|1023&s,t.push(240|r>>18,128|r>>12&63,128|r>>6&63,128|63&r)}else t.push(239,191,189)}else(64512&r)==56320?t.push(239,191,189):t.push(224|r>>12,128|r>>6&63,128|63&r)}return new Uint8Array(t)}function eZ(e,t){let n;switch(e){case eQ.BASE64:{let n=-1!==t.indexOf("-"),r=-1!==t.indexOf("_");if(n||r)throw eL(e,"Invalid character '"+(n?"-":"_")+"' found: is it base64url encoded?");break}case eQ.BASE64URL:{let n=-1!==t.indexOf("+"),r=-1!==t.indexOf("/");if(n||r)throw eL(e,"Invalid character '"+(n?"+":"/")+"' found: is it base64 encoded?");t=t.replace(/-/g,"+").replace(/_/g,"/")}}try{n=/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){if("undefined"==typeof atob)throw new ek(s.UNSUPPORTED_ENVIRONMENT,"base-64 is missing. Make sure to install the required polyfills. See https://firebase.google.com/docs/web/environments-js-sdk#polyfills for more information.");return atob(e)}(t)}catch(t){if(t.message.includes("polyfill"))throw t;throw eL(e,"Invalid character found")}let r=new Uint8Array(n.length);for(let e=0;e<n.length;e++)r[e]=n.charCodeAt(e);return r}class e0{constructor(e){this.base64=!1,this.contentType=null;let t=e.match(/^data:([^,]+)?,/);if(null===t)throw eL(eQ.DATA_URL,"Must be formatted 'data:[<mediatype>][;base64],<data>");let n=t[1]||null;null!=n&&(this.base64=function(e,t){let n=e.length>=t.length;return!!n&&e.substring(e.length-t.length)===t}(n,";base64"),this.contentType=this.base64?n.substring(0,n.length-7):n),this.rest=e.substring(e.indexOf(",")+1)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e1{constructor(e,t){let n=0,r="";eq(e)?(this.data_=e,n=e.size,r=e.type):e instanceof ArrayBuffer?(t?this.data_=new Uint8Array(e):(this.data_=new Uint8Array(e.byteLength),this.data_.set(new Uint8Array(e))),n=this.data_.length):e instanceof Uint8Array&&(t?this.data_=e:(this.data_=new Uint8Array(e.length),this.data_.set(e)),n=e.length),this.size_=n,this.type_=r}size(){return this.size_}type(){return this.type_}slice(e,t){if(eq(this.data_)){let n=this.data_,r=n.webkitSlice?n.webkitSlice(e,t):n.mozSlice?n.mozSlice(e,t):n.slice?n.slice(e,t):null;return null===r?null:new e1(r)}{let n=new Uint8Array(this.data_.buffer,e,t-e);return new e1(n,!0)}}static getBlob(...e){if(eB()){let t=e.map(e=>e instanceof e1?e.data_:e);return new e1(eH.apply(null,t))}{let t=e.map(e=>eV(e)?eX(eQ.RAW,e).data:e.data_),n=0;t.forEach(e=>{n+=e.byteLength});let r=new Uint8Array(n),i=0;return t.forEach(e=>{for(let t=0;t<e.length;t++)r[i++]=e[t]}),new e1(r,!0)}}uploadData(){return this.data_}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function e2(e){var t;let n;try{n=JSON.parse(e)}catch(e){return null}return"object"!=typeof(t=n)||Array.isArray(t)?null:n}function e3(e){let t=e.lastIndexOf("/",e.length-2);return -1===t?e:e.slice(t+1)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function e4(e,t){return t}class e6{constructor(e,t,n,r){this.server=e,this.local=t||e,this.writable=!!n,this.xform=r||e4}}let e5=null;function e9(){if(e5)return e5;let e=[];e.push(new e6("bucket")),e.push(new e6("generation")),e.push(new e6("metageneration")),e.push(new e6("name","fullPath",!0));let t=new e6("name");t.xform=function(e,t){return!eV(t)||t.length<2?t:e3(t)},e.push(t);let n=new e6("size");return n.xform=function(e,t){return void 0!==t?Number(t):t},e.push(n),e.push(new e6("timeCreated")),e.push(new e6("updated")),e.push(new e6("md5Hash",null,!0)),e.push(new e6("cacheControl",null,!0)),e.push(new e6("contentDisposition",null,!0)),e.push(new e6("contentEncoding",null,!0)),e.push(new e6("contentLanguage",null,!0)),e.push(new e6("contentType",null,!0)),e.push(new e6("metadata","customMetadata",!0)),e5=e}function e8(e,t,n){let r=e2(t);return null===r?null:function(e,t,n){let r={};r.type="file";let i=n.length;for(let e=0;e<i;e++){let i=n[e];r[i.local]=i.xform(r,t[i.server])}return Object.defineProperty(r,"ref",{get:function(){let t=r.bucket,n=r.fullPath,i=new eU(t,n);return e._makeStorageReference(i)}}),r}(e,r,n)}function e7(e,t){let n={},r=t.length;for(let i=0;i<r;i++){let r=t[i];r.writable&&(n[r.server]=e[r.local])}return JSON.stringify(n)}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let te="prefixes",tt="items";class tn{constructor(e,t,n,r){this.url=e,this.method=t,this.handler=n,this.timeout=r,this.urlParams={},this.headers={},this.body=null,this.errorHandler=null,this.progressCallback=null,this.successCodes=[200],this.additionalRetryCodes=[]}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function tr(e){if(!e)throw eC()}function ti(e,t){return function(n,r){let i=e8(e,r,t);return tr(null!==i),i}}function ts(e){return function(t,n){var r,i;let a;return 401===t.getStatus()?a=t.getErrorText().includes("Firebase App Check token is invalid")?new ek(s.UNAUTHORIZED_APP,"This app does not have permission to access Firebase Storage on this project."):new ek(s.UNAUTHENTICATED,"User is not authenticated, please authenticate using Firebase Authentication and try again."):402===t.getStatus()?(r=e.bucket,a=new ek(s.QUOTA_EXCEEDED,"Quota for bucket '"+r+"' exceeded, please view quota on https://firebase.google.com/pricing/.")):403===t.getStatus()?(i=e.path,a=new ek(s.UNAUTHORIZED,"User does not have permission to access '"+i+"'.")):a=n,a.status=t.getStatus(),a.serverResponse=n.serverResponse,a}}function ta(e){let t=ts(e);return function(n,r){let i=t(n,r);if(404===n.getStatus()){var a;a=e.path,i=new ek(s.OBJECT_NOT_FOUND,"Object '"+a+"' does not exist.")}return i.serverResponse=r.serverResponse,i}}function to(e,t,n){let r=t.fullServerUrl(),i=ez(r,e.host,e._protocol),s=e.maxOperationRetryTime,a=new tn(i,"GET",ti(e,n),s);return a.errorHandler=ta(t),a}function tl(e,t,n){let r=Object.assign({},n);return r.fullPath=e.path,r.size=t.size(),!r.contentType&&(r.contentType=t&&t.type()||"application/octet-stream"),r}class tu{constructor(e,t,n,r){this.current=e,this.total=t,this.finalized=!!n,this.metadata=r||null}}function tc(e,t){let n=null;try{n=e.getResponseHeader("X-Goog-Upload-Status")}catch(e){tr(!1)}return tr(!!n&&-1!==(t||["active"]).indexOf(n)),n}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let th={RUNNING:"running",PAUSED:"paused",SUCCESS:"success",CANCELED:"canceled",ERROR:"error"};function td(e){switch(e){case"running":case"pausing":case"canceling":return th.RUNNING;case"paused":return th.PAUSED;case"success":return th.SUCCESS;case"canceled":return th.CANCELED;default:return th.ERROR}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tf{constructor(e,t,n){"function"==typeof e||null!=t||null!=n?(this.next=e,this.error=null!=t?t:void 0,this.complete=null!=n?n:void 0):(this.next=e.next,this.error=e.error,this.complete=e.complete)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function tp(e){return(...t)=>{Promise.resolve().then(()=>e(...t))}}class tm{constructor(){this.sent_=!1,this.xhr_=new XMLHttpRequest,this.initXhr(),this.errorCode_=a.NO_ERROR,this.sendPromise_=new Promise(e=>{this.xhr_.addEventListener("abort",()=>{this.errorCode_=a.ABORT,e()}),this.xhr_.addEventListener("error",()=>{this.errorCode_=a.NETWORK_ERROR,e()}),this.xhr_.addEventListener("load",()=>{e()})})}send(e,t,n,r){if(this.sent_)throw eM("cannot .send() more than once");if(this.sent_=!0,this.xhr_.open(t,e,!0),void 0!==r)for(let e in r)r.hasOwnProperty(e)&&this.xhr_.setRequestHeader(e,r[e].toString());return void 0!==n?this.xhr_.send(n):this.xhr_.send(),this.sendPromise_}getErrorCode(){if(!this.sent_)throw eM("cannot .getErrorCode() before sending");return this.errorCode_}getStatus(){if(!this.sent_)throw eM("cannot .getStatus() before sending");try{return this.xhr_.status}catch(e){return -1}}getResponse(){if(!this.sent_)throw eM("cannot .getResponse() before sending");return this.xhr_.response}getErrorText(){if(!this.sent_)throw eM("cannot .getErrorText() before sending");return this.xhr_.statusText}abort(){this.xhr_.abort()}getResponseHeader(e){return this.xhr_.getResponseHeader(e)}addUploadProgressListener(e){null!=this.xhr_.upload&&this.xhr_.upload.addEventListener("progress",e)}removeUploadProgressListener(e){null!=this.xhr_.upload&&this.xhr_.upload.removeEventListener("progress",e)}}class tg extends tm{initXhr(){this.xhr_.responseType="text"}}function ty(){return new tg}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tv{constructor(e,t,n=null){this._transferred=0,this._needToFetchStatus=!1,this._needToFetchMetadata=!1,this._observers=[],this._error=void 0,this._uploadUrl=void 0,this._request=void 0,this._chunkMultiplier=1,this._resolve=void 0,this._reject=void 0,this._ref=e,this._blob=t,this._metadata=n,this._mappings=e9(),this._resumable=this._shouldDoResumable(this._blob),this._state="running",this._errorHandler=e=>{if(this._request=void 0,this._chunkMultiplier=1,e._codeEquals(s.CANCELED))this._needToFetchStatus=!0,this.completeTransitions_();else{let t=this.isExponentialBackoffExpired();if(eG(e.status,[])){if(t)e=ex();else{this.sleepTime=Math.max(2*this.sleepTime,1e3),this._needToFetchStatus=!0,this.completeTransitions_();return}}this._error=e,this._transition("error")}},this._metadataErrorHandler=e=>{this._request=void 0,e._codeEquals(s.CANCELED)?this.completeTransitions_():(this._error=e,this._transition("error"))},this.sleepTime=0,this.maxSleepTime=this._ref.storage.maxUploadRetryTime,this._promise=new Promise((e,t)=>{this._resolve=e,this._reject=t,this._start()}),this._promise.then(null,()=>{})}isExponentialBackoffExpired(){return this.sleepTime>this.maxSleepTime}_makeProgressCallback(){let e=this._transferred;return t=>this._updateProgress(e+t)}_shouldDoResumable(e){return e.size()>262144}_start(){"running"===this._state&&void 0===this._request&&(this._resumable?void 0===this._uploadUrl?this._createResumable():this._needToFetchStatus?this._fetchStatus():this._needToFetchMetadata?this._fetchMetadata():this.pendingTimeout=setTimeout(()=>{this.pendingTimeout=void 0,this._continueUpload()},this.sleepTime):this._oneShotUpload())}_resolveToken(e){Promise.all([this._ref.storage._getAuthToken(),this._ref.storage._getAppCheckToken()]).then(([t,n])=>{switch(this._state){case"running":e(t,n);break;case"canceling":this._transition("canceled");break;case"pausing":this._transition("paused")}})}_createResumable(){this._resolveToken((e,t)=>{let n=function(e,t,n,r,i){let s=t.bucketOnlyServerUrl(),a=tl(t,r,i),o={name:a.fullPath},l=ez(s,e.host,e._protocol),u={"X-Goog-Upload-Protocol":"resumable","X-Goog-Upload-Command":"start","X-Goog-Upload-Header-Content-Length":`${r.size()}`,"X-Goog-Upload-Header-Content-Type":a.contentType,"Content-Type":"application/json; charset=utf-8"},c=e7(a,n),h=e.maxUploadRetryTime,d=new tn(l,"POST",function(e){let t;tc(e);try{t=e.getResponseHeader("X-Goog-Upload-URL")}catch(e){tr(!1)}return tr(eV(t)),t},h);return d.urlParams=o,d.headers=u,d.body=c,d.errorHandler=ts(t),d}(this._ref.storage,this._ref._location,this._mappings,this._blob,this._metadata),r=this._ref.storage._makeRequest(n,ty,e,t);this._request=r,r.getPromise().then(e=>{this._request=void 0,this._uploadUrl=e,this._needToFetchStatus=!1,this.completeTransitions_()},this._errorHandler)})}_fetchStatus(){let e=this._uploadUrl;this._resolveToken((t,n)=>{let r=function(e,t,n,r){let i=e.maxUploadRetryTime,s=new tn(n,"POST",function(e){let t=tc(e,["active","final"]),n=null;try{n=e.getResponseHeader("X-Goog-Upload-Size-Received")}catch(e){tr(!1)}n||tr(!1);let i=Number(n);return tr(!isNaN(i)),new tu(i,r.size(),"final"===t)},i);return s.headers={"X-Goog-Upload-Command":"query"},s.errorHandler=ts(t),s}(this._ref.storage,this._ref._location,e,this._blob),i=this._ref.storage._makeRequest(r,ty,t,n);this._request=i,i.getPromise().then(e=>{this._request=void 0,this._updateProgress(e.current),this._needToFetchStatus=!1,e.finalized&&(this._needToFetchMetadata=!0),this.completeTransitions_()},this._errorHandler)})}_continueUpload(){let e=262144*this._chunkMultiplier,t=new tu(this._transferred,this._blob.size()),n=this._uploadUrl;this._resolveToken((r,i)=>{let a;try{a=function(e,t,n,r,i,a,o,l){let u=new tu(0,0);if(o?(u.current=o.current,u.total=o.total):(u.current=0,u.total=r.size()),r.size()!==u.total)throw new ek(s.SERVER_FILE_WRONG_SIZE,"Server recorded incorrect upload file size, please retry the upload.");let c=u.total-u.current,h=c;i>0&&(h=Math.min(h,i));let d=u.current,f=d+h,p="";p=0===h?"finalize":c===h?"upload, finalize":"upload";let m={"X-Goog-Upload-Command":p,"X-Goog-Upload-Offset":`${u.current}`},g=r.slice(d,f);if(null===g)throw eR();let y=t.maxUploadRetryTime,v=new tn(n,"POST",function(e,n){let i;let s=tc(e,["active","final"]),o=u.current+h,l=r.size();return i="final"===s?ti(t,a)(e,n):null,new tu(o,l,"final"===s,i)},y);return v.headers=m,v.body=g.uploadData(),v.progressCallback=l||null,v.errorHandler=ts(e),v}(this._ref._location,this._ref.storage,n,this._blob,e,this._mappings,t,this._makeProgressCallback())}catch(e){this._error=e,this._transition("error");return}let o=this._ref.storage._makeRequest(a,ty,r,i,!1);this._request=o,o.getPromise().then(e=>{this._increaseMultiplier(),this._request=void 0,this._updateProgress(e.current),e.finalized?(this._metadata=e.metadata,this._transition("success")):this.completeTransitions_()},this._errorHandler)})}_increaseMultiplier(){let e=262144*this._chunkMultiplier;2*e<33554432&&(this._chunkMultiplier*=2)}_fetchMetadata(){this._resolveToken((e,t)=>{let n=to(this._ref.storage,this._ref._location,this._mappings),r=this._ref.storage._makeRequest(n,ty,e,t);this._request=r,r.getPromise().then(e=>{this._request=void 0,this._metadata=e,this._transition("success")},this._metadataErrorHandler)})}_oneShotUpload(){this._resolveToken((e,t)=>{let n=function(e,t,n,r,i){let s=t.bucketOnlyServerUrl(),a={"X-Goog-Upload-Protocol":"multipart"},o=function(){let e="";for(let t=0;t<2;t++)e+=Math.random().toString().slice(2);return e}();a["Content-Type"]="multipart/related; boundary="+o;let l=tl(t,r,i),u=e7(l,n),c="--"+o+"\r\nContent-Type: application/json; charset=utf-8\r\n\r\n"+u+"\r\n--"+o+"\r\nContent-Type: "+l.contentType+"\r\n\r\n",h=e1.getBlob(c,r,"\r\n--"+o+"--");if(null===h)throw eR();let d={name:l.fullPath},f=ez(s,e.host,e._protocol),p=e.maxUploadRetryTime,m=new tn(f,"POST",ti(e,n),p);return m.urlParams=d,m.headers=a,m.body=h.uploadData(),m.errorHandler=ts(t),m}(this._ref.storage,this._ref._location,this._mappings,this._blob,this._metadata),r=this._ref.storage._makeRequest(n,ty,e,t);this._request=r,r.getPromise().then(e=>{this._request=void 0,this._metadata=e,this._updateProgress(this._blob.size()),this._transition("success")},this._errorHandler)})}_updateProgress(e){let t=this._transferred;this._transferred=e,this._transferred!==t&&this._notifyObservers()}_transition(e){if(this._state!==e)switch(e){case"canceling":case"pausing":this._state=e,void 0!==this._request?this._request.cancel():this.pendingTimeout&&(clearTimeout(this.pendingTimeout),this.pendingTimeout=void 0,this.completeTransitions_());break;case"running":let t="paused"===this._state;this._state=e,t&&(this._notifyObservers(),this._start());break;case"paused":case"error":case"success":this._state=e,this._notifyObservers();break;case"canceled":this._error=eN(),this._state=e,this._notifyObservers()}}completeTransitions_(){switch(this._state){case"pausing":this._transition("paused");break;case"canceling":this._transition("canceled");break;case"running":this._start()}}get snapshot(){let e=td(this._state);return{bytesTransferred:this._transferred,totalBytes:this._blob.size(),state:e,metadata:this._metadata,task:this,ref:this._ref}}on(e,t,n,r){let i=new tf(t||void 0,n||void 0,r||void 0);return this._addObserver(i),()=>{this._removeObserver(i)}}then(e,t){return this._promise.then(e,t)}catch(e){return this.then(null,e)}_addObserver(e){this._observers.push(e),this._notifyObserver(e)}_removeObserver(e){let t=this._observers.indexOf(e);-1!==t&&this._observers.splice(t,1)}_notifyObservers(){this._finishPromise();let e=this._observers.slice();e.forEach(e=>{this._notifyObserver(e)})}_finishPromise(){if(void 0!==this._resolve){let e=!0;switch(td(this._state)){case th.SUCCESS:tp(this._resolve.bind(null,this.snapshot))();break;case th.CANCELED:case th.ERROR:let t=this._reject;tp(t.bind(null,this._error))();break;default:e=!1}e&&(this._resolve=void 0,this._reject=void 0)}}_notifyObserver(e){let t=td(this._state);switch(t){case th.RUNNING:case th.PAUSED:e.next&&tp(e.next.bind(e,this.snapshot))();break;case th.SUCCESS:e.complete&&tp(e.complete.bind(e))();break;case th.CANCELED:case th.ERROR:default:e.error&&tp(e.error.bind(e,this._error))()}}resume(){let e="paused"===this._state||"pausing"===this._state;return e&&this._transition("running"),e}pause(){let e="running"===this._state;return e&&this._transition("pausing"),e}cancel(){let e="running"===this._state||"pausing"===this._state;return e&&this._transition("canceling"),e}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tw{constructor(e,t){this._service=e,t instanceof eU?this._location=t:this._location=eU.makeFromUrl(t,e.host)}toString(){return"gs://"+this._location.bucket+"/"+this._location.path}_newRef(e,t){return new tw(e,t)}get root(){let e=new eU(this._location.bucket,"");return this._newRef(this._service,e)}get bucket(){return this._location.bucket}get fullPath(){return this._location.path}get name(){return e3(this._location.path)}get storage(){return this._service}get parent(){let e=/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){if(0===e.length)return null;let t=e.lastIndexOf("/");if(-1===t)return"";let n=e.slice(0,t);return n}(this._location.path);if(null===e)return null;let t=new eU(this._location.bucket,e);return new tw(this._service,t)}_throwIfRoot(e){if(""===this._location.path)throw eP(e)}}async function t_(e,t,n){let r=await tb(e,{pageToken:n});t.prefixes.push(...r.prefixes),t.items.push(...r.items),null!=r.nextPageToken&&await t_(e,t,r.nextPageToken)}function tb(e,t){null!=t&&"number"==typeof t.maxResults&&ej("options.maxResults",1,1e3,t.maxResults);let n=t||{},r=function(e,t,n,r,i){var s;let a={};t.isRoot?a.prefix="":a.prefix=t.path+"/",n&&n.length>0&&(a.delimiter=n),r&&(a.pageToken=r),i&&(a.maxResults=i);let o=t.bucketOnlyServerUrl(),l=ez(o,e.host,e._protocol),u=e.maxOperationRetryTime,c=new tn(l,"GET",(s=t.bucket,function(t,n){let r=function(e,t,n){let r=e2(n);return null===r?null:function(e,t,n){let r={prefixes:[],items:[],nextPageToken:n.nextPageToken};if(n[te])for(let i of n[te]){let n=i.replace(/\/$/,""),s=e._makeStorageReference(new eU(t,n));r.prefixes.push(s)}if(n[tt])for(let i of n[tt]){let n=e._makeStorageReference(new eU(t,i.name));r.items.push(n)}return r}(e,t,r)}(e,s,n);return tr(null!==r),r}),u);return c.urlParams=a,c.errorHandler=ts(t),c}(e.storage,e._location,"/",n.pageToken,n.maxResults);return e.storage.makeRequestWithTokens(r,ty)}function tI(e,t){let n=function(e,t){let n=t.split("/").filter(e=>e.length>0).join("/");return 0===e.length?n:e+"/"+n}(e._location.path,t),r=new eU(e._location.bucket,n);return new tw(e.storage,r)}function tT(e,t){let n=null==t?void 0:t[eS];return null==n?null:eU.makeFromBucketSpec(n,e)}class tE{constructor(e,t,n,r,i){this.app=e,this._authProvider=t,this._appCheckProvider=n,this._url=r,this._firebaseVersion=i,this._bucket=null,this._host=eE,this._protocol="https",this._appId=null,this._deleted=!1,this._maxOperationRetryTime=12e4,this._maxUploadRetryTime=6e5,this._requests=new Set,null!=r?this._bucket=eU.makeFromBucketSpec(r,this._host):this._bucket=tT(this._host,this.app.options)}get host(){return this._host}set host(e){this._host=e,null!=this._url?this._bucket=eU.makeFromBucketSpec(this._url,e):this._bucket=tT(e,this.app.options)}get maxUploadRetryTime(){return this._maxUploadRetryTime}set maxUploadRetryTime(e){ej("time",0,Number.POSITIVE_INFINITY,e),this._maxUploadRetryTime=e}get maxOperationRetryTime(){return this._maxOperationRetryTime}set maxOperationRetryTime(e){ej("time",0,Number.POSITIVE_INFINITY,e),this._maxOperationRetryTime=e}async _getAuthToken(){if(this._overrideAuthToken)return this._overrideAuthToken;let e=this._authProvider.getImmediate({optional:!0});if(e){let t=await e.getToken();if(null!==t)return t.accessToken}return null}async _getAppCheckToken(){let e=this._appCheckProvider.getImmediate({optional:!0});if(e){let t=await e.getToken();return t.token}return null}_delete(){return this._deleted||(this._deleted=!0,this._requests.forEach(e=>e.cancel()),this._requests.clear()),Promise.resolve()}_makeStorageReference(e){return new tw(this,e)}_makeRequest(e,t,n,r,i=!0){if(this._deleted)return new eF(eO());{let s=function(e,t,n,r,i,s,a=!0){var o,l,u;let c=e$(e.urlParams),h=e.url+c,d=Object.assign({},e.headers);return o=d,t&&(o["X-Firebase-GMPID"]=t),l=d,null!==n&&n.length>0&&(l.Authorization="Firebase "+n),d["X-Firebase-Storage-Version"]="webjs/"+(null!=s?s:"AppManager"),u=d,null!==r&&(u["X-Firebase-AppCheck"]=r),new eK(h,e.method,d,e.body,e.successCodes,e.additionalRetryCodes,e.handler,e.errorHandler,e.timeout,e.progressCallback,i,a)}(e,this._appId,n,r,t,this._firebaseVersion,i);return this._requests.add(s),s.getPromise().then(()=>this._requests.delete(s),()=>this._requests.delete(s)),s}}async makeRequestWithTokens(e,t){let[n,r]=await Promise.all([this._getAuthToken(),this._getAppCheckToken()]);return this._makeRequest(e,t,n,r).getPromise()}}let tS="@firebase/storage",tk="0.11.1";function tA(e,t){return function(e,t){if(!(t&&/^[A-Za-z]+:\/\//.test(t)))return function e(t,n){if(t instanceof tE){if(null==t._bucket)throw new ek(s.NO_DEFAULT_BUCKET,"No default bucket found. Did you set the '"+eS+"' property when initializing the app?");let r=new tw(t,t._bucket);return null!=n?e(r,n):r}return void 0!==n?tI(t,n):t}(e,t);if(e instanceof tE)return new tw(e,t);throw eD("To use ref(service, url), the first argument must be a Storage instance.")}(e=(0,o.m9)(e),t)}(0,u._registerComponent)(new l.wA("storage",function(e,{instanceIdentifier:t}){let n=e.getProvider("app").getImmediate(),r=e.getProvider("auth-internal"),i=e.getProvider("app-check-internal");return new tE(n,r,i,t,u.SDK_VERSION)},"PUBLIC").setMultipleInstances(!0)),(0,u.registerVersion)(tS,tk,""),(0,u.registerVersion)(tS,tk,"esm2017");/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tC{constructor(e,t,n){this._delegate=e,this.task=t,this.ref=n}get bytesTransferred(){return this._delegate.bytesTransferred}get metadata(){return this._delegate.metadata}get state(){return this._delegate.state}get totalBytes(){return this._delegate.totalBytes}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tx{constructor(e,t){this._delegate=e,this._ref=t,this.cancel=this._delegate.cancel.bind(this._delegate),this.catch=this._delegate.catch.bind(this._delegate),this.pause=this._delegate.pause.bind(this._delegate),this.resume=this._delegate.resume.bind(this._delegate)}get snapshot(){return new tC(this._delegate.snapshot,this,this._ref)}then(e,t){return this._delegate.then(t=>{if(e)return e(new tC(t,this,this._ref))},t)}on(e,t,n,r){let i;return t&&(i="function"==typeof t?e=>t(new tC(e,this,this._ref)):{next:t.next?e=>t.next(new tC(e,this,this._ref)):void 0,complete:t.complete||void 0,error:t.error||void 0}),this._delegate.on(e,i,n||void 0,r||void 0)}}class tN{constructor(e,t){this._delegate=e,this._service=t}get prefixes(){return this._delegate.prefixes.map(e=>new tR(e,this._service))}get items(){return this._delegate.items.map(e=>new tR(e,this._service))}get nextPageToken(){return this._delegate.nextPageToken||null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tR{constructor(e,t){this._delegate=e,this.storage=t}get name(){return this._delegate.name}get bucket(){return this._delegate.bucket}get fullPath(){return this._delegate.fullPath}toString(){return this._delegate.toString()}child(e){let t=tI(this._delegate,e);return new tR(t,this.storage)}get root(){return new tR(this._delegate.root,this.storage)}get parent(){let e=this._delegate.parent;return null==e?null:new tR(e,this.storage)}put(e,t){var n,r;return this._throwIfRoot("put"),new tx((n=this._delegate,(r=n=(0,o.m9)(n))._throwIfRoot("uploadBytesResumable"),new tv(r,new e1(e),t)),this)}putString(e,t=eQ.RAW,n){this._throwIfRoot("putString");let r=eX(t,e),i=Object.assign({},n);return null==i.contentType&&null!=r.contentType&&(i.contentType=r.contentType),new tx(new tv(this._delegate,new e1(r.data,!0),i),this)}listAll(){var e;return(e=this._delegate,function(e){let t={prefixes:[],items:[]};return t_(e,t).then(()=>t)}(e=(0,o.m9)(e))).then(e=>new tN(e,this.storage))}list(e){var t;return(t=this._delegate,tb(t=(0,o.m9)(t),e||void 0)).then(e=>new tN(e,this.storage))}getMetadata(){var e;return e=this._delegate,function(e){e._throwIfRoot("getMetadata");let t=to(e.storage,e._location,e9());return e.storage.makeRequestWithTokens(t,ty)}(e=(0,o.m9)(e))}updateMetadata(e){var t;return t=this._delegate,function(e,t){e._throwIfRoot("updateMetadata");let n=function(e,t,n,r){let i=t.fullServerUrl(),s=ez(i,e.host,e._protocol),a=e7(n,r),o=e.maxOperationRetryTime,l=new tn(s,"PATCH",ti(e,r),o);return l.headers={"Content-Type":"application/json; charset=utf-8"},l.body=a,l.errorHandler=ta(t),l}(e.storage,e._location,t,e9());return e.storage.makeRequestWithTokens(n,ty)}(t=(0,o.m9)(t),e)}getDownloadURL(){var e;return e=this._delegate,function(e){e._throwIfRoot("getDownloadURL");let t=function(e,t,n){let r=t.fullServerUrl(),i=ez(r,e.host,e._protocol),s=e.maxOperationRetryTime,a=new tn(i,"GET",function(t,r){let i=e8(e,r,n);return tr(null!==i),function(e,t,n,r){let i=e2(t);if(null===i||!eV(i.downloadTokens))return null;let s=i.downloadTokens;if(0===s.length)return null;let a=encodeURIComponent,o=s.split(","),l=o.map(t=>{let i=e.bucket,s=e.fullPath,o="/b/"+a(i)+"/o/"+a(s),l=ez(o,n,r),u=e$({alt:"media",token:t});return l+u});return l[0]}(i,r,e.host,e._protocol)},s);return a.errorHandler=ta(t),a}(e.storage,e._location,e9());return e.storage.makeRequestWithTokens(t,ty).then(e=>{if(null===e)throw new ek(s.NO_DOWNLOAD_URL,"The given file does not have any download URLs.");return e})}(e=(0,o.m9)(e))}delete(){var e;return this._throwIfRoot("delete"),e=this._delegate,function(e){e._throwIfRoot("deleteObject");let t=function(e,t){let n=t.fullServerUrl(),r=ez(n,e.host,e._protocol),i=e.maxOperationRetryTime,s=new tn(r,"DELETE",function(e,t){},i);return s.successCodes=[200,204],s.errorHandler=ta(t),s}(e.storage,e._location);return e.storage.makeRequestWithTokens(t,ty)}(e=(0,o.m9)(e))}_throwIfRoot(e){if(""===this._delegate._location.path)throw eP(e)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tD{constructor(e,t){this.app=e,this._delegate=t}get maxOperationRetryTime(){return this._delegate.maxOperationRetryTime}get maxUploadRetryTime(){return this._delegate.maxUploadRetryTime}ref(e){if(tO(e))throw eD("ref() expected a child path but got a URL, use refFromURL instead.");return new tR(tA(this._delegate,e),this)}refFromURL(e){if(!tO(e))throw eD("refFromURL() expected a full URL but got a child path, use ref() instead.");try{eU.makeFromUrl(e,this._delegate.host)}catch(e){throw eD("refFromUrl() expected a valid full URL but got an invalid one.")}return new tR(tA(this._delegate,e),this)}setMaxUploadRetryTime(e){this._delegate.maxUploadRetryTime=e}setMaxOperationRetryTime(e){this._delegate.maxOperationRetryTime=e}useEmulator(e,t,n={}){!function(e,t,n,r={}){!function(e,t,n,r={}){e.host=`${t}:${n}`,e._protocol="http";let{mockUserToken:i}=r;i&&(e._overrideAuthToken="string"==typeof i?i:(0,o.Sg)(i,e.app.options.projectId))}(e,t,n,r)}(this._delegate,e,t,n)}}function tO(e){return/^[A-Za-z]+:\/\//.test(e)}f.INTERNAL.registerComponent(new l.wA("storage-compat",function(e,{instanceIdentifier:t}){let n=e.getProvider("app-compat").getImmediate(),r=e.getProvider("storage").getImmediate({identifier:t}),i=new tD(n,r);return i},"PUBLIC").setServiceProps({TaskState:th,TaskEvent:{STATE_CHANGED:"state_changed"},StringFormat:eQ,Storage:tD,Reference:tR}).setMultipleInstances(!0)),f.registerVersion("@firebase/storage-compat","0.3.1"),f.apps.length||f.initializeApp({apiKey:"AIzaSyCD4CqdGD5u7p1O_mMkmBeLrS9EtrWv3Mo",authDomain:"the-film-circle-d4cf1.firebaseapp.com",projectId:"the-film-circle-d4cf1",storageBucket:"the-film-circle-d4cf1.appspot.com",messagingSenderId:"333168772321",appId:"1:333168772321:web:27fcbb58aa8b53d1a6a3a0",measurementId:"G-6HX1MC68WR"});let tP=f.auth(),tL=new f.auth.GoogleAuthProvider,tM=f.firestore(),tU=f.storage(),tF=f.firestore.Timestamp.fromMillis,tV=f.firestore.FieldValue.serverTimestamp,tq=f.storage.TaskEvent.STATE_CHANGED},227:function(e,t){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.getDomainLocale=function(e,t,n,r){return!1},("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},9749:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.default=void 0;var r=n(6495).Z,i=n(2648).Z,s=n(1598).Z,a=n(7273).Z,o=s(n(7294)),l=i(n(3121)),u=n(2675),c=n(139),h=n(8730);n(7238);var d=i(n(9824));let f={deviceSizes:[640,750,828,1080,1200,1920,2048,3840],imageSizes:[16,32,48,64,96,128,256,384],path:"/_next/image",loader:"default",dangerouslyAllowSVG:!1,unoptimized:!1};function p(e){return void 0!==e.default}function m(e){return"number"==typeof e||void 0===e?e:"string"==typeof e&&/^[0-9]+$/.test(e)?parseInt(e,10):NaN}function g(e,t,n,i,s,a,o){if(!e||e["data-loaded-src"]===t)return;e["data-loaded-src"]=t;let l="decode"in e?e.decode():Promise.resolve();l.catch(()=>{}).then(()=>{if(e.parentNode){if("blur"===n&&a(!0),null==i?void 0:i.current){let t=new Event("load");Object.defineProperty(t,"target",{writable:!1,value:e});let n=!1,s=!1;i.current(r({},t,{nativeEvent:t,currentTarget:e,target:e,isDefaultPrevented:()=>n,isPropagationStopped:()=>s,persist:()=>{},preventDefault:()=>{n=!0,t.preventDefault()},stopPropagation:()=>{s=!0,t.stopPropagation()}}))}(null==s?void 0:s.current)&&s.current(e)}})}let y=o.forwardRef((e,t)=>{var{imgAttributes:n,heightInt:i,widthInt:s,qualityInt:l,className:u,imgStyle:c,blurStyle:h,isLazy:d,fill:f,placeholder:p,loading:m,srcString:y,config:v,unoptimized:w,loader:_,onLoadRef:b,onLoadingCompleteRef:I,setBlurComplete:T,setShowAltText:E,onLoad:S,onError:k}=e,A=a(e,["imgAttributes","heightInt","widthInt","qualityInt","className","imgStyle","blurStyle","isLazy","fill","placeholder","loading","srcString","config","unoptimized","loader","onLoadRef","onLoadingCompleteRef","setBlurComplete","setShowAltText","onLoad","onError"]);return m=d?"lazy":m,o.default.createElement(o.default.Fragment,null,o.default.createElement("img",Object.assign({},A,n,{width:s,height:i,decoding:"async","data-nimg":f?"fill":"1",className:u,loading:m,style:r({},c,h),ref:o.useCallback(e=>{t&&("function"==typeof t?t(e):"object"==typeof t&&(t.current=e)),e&&(k&&(e.src=e.src),e.complete&&g(e,y,p,b,I,T,w))},[y,p,b,I,T,k,w,t]),onLoad:e=>{let t=e.currentTarget;g(t,y,p,b,I,T,w)},onError:e=>{E(!0),"blur"===p&&T(!0),k&&k(e)}})))}),v=o.forwardRef((e,t)=>{let n,i;var s,{src:g,sizes:v,unoptimized:w=!1,priority:_=!1,loading:b,className:I,quality:T,width:E,height:S,fill:k,style:A,onLoad:C,onLoadingComplete:x,placeholder:N="empty",blurDataURL:R,layout:D,objectFit:O,objectPosition:P,lazyBoundary:L,lazyRoot:M}=e,U=a(e,["src","sizes","unoptimized","priority","loading","className","quality","width","height","fill","style","onLoad","onLoadingComplete","placeholder","blurDataURL","layout","objectFit","objectPosition","lazyBoundary","lazyRoot"]);let F=o.useContext(h.ImageConfigContext),V=o.useMemo(()=>{let e=f||F||c.imageConfigDefault,t=[...e.deviceSizes,...e.imageSizes].sort((e,t)=>e-t),n=e.deviceSizes.sort((e,t)=>e-t);return r({},e,{allSizes:t,deviceSizes:n})},[F]),q=U,B=q.loader||d.default;delete q.loader;let j="__next_img_default"in B;if(j){if("custom"===V.loader)throw Error('Image with src "'.concat(g,'" is missing "loader" prop.')+"\nRead more: https://nextjs.org/docs/messages/next-image-missing-loader")}else{let e=B;B=t=>{let{config:n}=t,r=a(t,["config"]);return e(r)}}if(D){"fill"===D&&(k=!0);let e={intrinsic:{maxWidth:"100%",height:"auto"},responsive:{width:"100%",height:"auto"}}[D];e&&(A=r({},A,e));let t={responsive:"100vw",fill:"100vw"}[D];t&&!v&&(v=t)}let z="",$=m(E),G=m(S);if("object"==typeof(s=g)&&(p(s)||void 0!==s.src)){let e=p(g)?g.default:g;if(!e.src)throw Error("An object should only be passed to the image component src parameter if it comes from a static image import. It must include src. Received ".concat(JSON.stringify(e)));if(!e.height||!e.width)throw Error("An object should only be passed to the image component src parameter if it comes from a static image import. It must include height and width. Received ".concat(JSON.stringify(e)));if(n=e.blurWidth,i=e.blurHeight,R=R||e.blurDataURL,z=e.src,!k){if($||G){if($&&!G){let t=$/e.width;G=Math.round(e.height*t)}else if(!$&&G){let t=G/e.height;$=Math.round(e.width*t)}}else $=e.width,G=e.height}}let K=!_&&("lazy"===b||void 0===b);((g="string"==typeof g?g:z).startsWith("data:")||g.startsWith("blob:"))&&(w=!0,K=!1),V.unoptimized&&(w=!0),j&&g.endsWith(".svg")&&!V.dangerouslyAllowSVG&&(w=!0);let[W,H]=o.useState(!1),[Q,Y]=o.useState(!1),X=m(T),J=Object.assign(k?{position:"absolute",height:"100%",width:"100%",left:0,top:0,right:0,bottom:0,objectFit:O,objectPosition:P}:{},Q?{}:{color:"transparent"},A),Z="blur"===N&&R&&!W?{backgroundSize:J.objectFit||"cover",backgroundPosition:J.objectPosition||"50% 50%",backgroundRepeat:"no-repeat",backgroundImage:'url("data:image/svg+xml;charset=utf-8,'.concat(u.getImageBlurSvg({widthInt:$,heightInt:G,blurWidth:n,blurHeight:i,blurDataURL:R}),'")')}:{},ee=function(e){let{config:t,src:n,unoptimized:r,width:i,quality:s,sizes:a,loader:o}=e;if(r)return{src:n,srcSet:void 0,sizes:void 0};let{widths:l,kind:u}=function(e,t,n){let{deviceSizes:r,allSizes:i}=e;if(n){let e=/(^|\s)(1?\d?\d)vw/g,t=[];for(let r;r=e.exec(n);r)t.push(parseInt(r[2]));if(t.length){let e=.01*Math.min(...t);return{widths:i.filter(t=>t>=r[0]*e),kind:"w"}}return{widths:i,kind:"w"}}if("number"!=typeof t)return{widths:r,kind:"w"};let s=[...new Set([t,2*t].map(e=>i.find(t=>t>=e)||i[i.length-1]))];return{widths:s,kind:"x"}}(t,i,a),c=l.length-1;return{sizes:a||"w"!==u?a:"100vw",srcSet:l.map((e,r)=>"".concat(o({config:t,src:n,quality:s,width:e})," ").concat("w"===u?e:r+1).concat(u)).join(", "),src:o({config:t,src:n,quality:s,width:l[c]})}}({config:V,src:g,unoptimized:w,width:$,quality:X,sizes:v,loader:B}),et=g,en={imageSrcSet:ee.srcSet,imageSizes:ee.sizes,crossOrigin:q.crossOrigin},er=o.useRef(C);o.useEffect(()=>{er.current=C},[C]);let ei=o.useRef(x);o.useEffect(()=>{ei.current=x},[x]);let es=r({isLazy:K,imgAttributes:ee,heightInt:G,widthInt:$,qualityInt:X,className:I,imgStyle:J,blurStyle:Z,loading:b,config:V,fill:k,unoptimized:w,placeholder:N,loader:B,srcString:et,onLoadRef:er,onLoadingCompleteRef:ei,setBlurComplete:H,setShowAltText:Y},q);return o.default.createElement(o.default.Fragment,null,o.default.createElement(y,Object.assign({},es,{ref:t})),_?o.default.createElement(l.default,null,o.default.createElement("link",Object.assign({key:"__nimg-"+ee.src+ee.srcSet+ee.sizes,rel:"preload",as:"image",href:ee.srcSet?void 0:ee.src},en))):null)});t.default=v,("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},1551:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.default=void 0;var r=n(2648).Z,i=n(7273).Z,s=r(n(7294)),a=n(1003),o=n(7795),l=n(4465),u=n(2692),c=n(8245),h=n(9246),d=n(227),f=n(3468);let p=new Set;function m(e,t,n,r){if(a.isLocalURL(t)){if(!r.bypassPrefetchedCheck){let i=void 0!==r.locale?r.locale:"locale"in e?e.locale:void 0,s=t+"%"+n+"%"+i;if(p.has(s))return;p.add(s)}Promise.resolve(e.prefetch(t,n,r)).catch(e=>{})}}function g(e){return"string"==typeof e?e:o.formatUrl(e)}let y=s.default.forwardRef(function(e,t){let n,r;let{href:o,as:p,children:y,prefetch:v,passHref:w,replace:_,shallow:b,scroll:I,locale:T,onClick:E,onMouseEnter:S,onTouchStart:k,legacyBehavior:A=!1}=e,C=i(e,["href","as","children","prefetch","passHref","replace","shallow","scroll","locale","onClick","onMouseEnter","onTouchStart","legacyBehavior"]);n=y,A&&("string"==typeof n||"number"==typeof n)&&(n=s.default.createElement("a",null,n));let x=!1!==v,N=s.default.useContext(u.RouterContext),R=s.default.useContext(c.AppRouterContext),D=null!=N?N:R,O=!N,{href:P,as:L}=s.default.useMemo(()=>{if(!N){let e=g(o);return{href:e,as:p?g(p):e}}let[e,t]=a.resolveHref(N,o,!0);return{href:e,as:p?a.resolveHref(N,p):t||e}},[N,o,p]),M=s.default.useRef(P),U=s.default.useRef(L);A&&(r=s.default.Children.only(n));let F=A?r&&"object"==typeof r&&r.ref:t,[V,q,B]=h.useIntersection({rootMargin:"200px"}),j=s.default.useCallback(e=>{(U.current!==L||M.current!==P)&&(B(),U.current=L,M.current=P),V(e),F&&("function"==typeof F?F(e):"object"==typeof F&&(F.current=e))},[L,F,P,B,V]);s.default.useEffect(()=>{D&&q&&x&&m(D,P,L,{locale:T})},[L,P,q,T,x,null==N?void 0:N.locale,D]);let z={ref:j,onClick(e){A||"function"!=typeof E||E(e),A&&r.props&&"function"==typeof r.props.onClick&&r.props.onClick(e),D&&!e.defaultPrevented&&function(e,t,n,r,i,o,l,u,c,h){let{nodeName:d}=e.currentTarget,f="A"===d.toUpperCase();if(f&&(function(e){let{target:t}=e.currentTarget;return t&&"_self"!==t||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.nativeEvent&&2===e.nativeEvent.which}(e)||!a.isLocalURL(n)))return;e.preventDefault();let p=()=>{"beforePopState"in t?t[i?"replace":"push"](n,r,{shallow:o,locale:u,scroll:l}):t[i?"replace":"push"](r||n,{forceOptimisticNavigation:!h})};c?s.default.startTransition(p):p()}(e,D,P,L,_,b,I,T,O,x)},onMouseEnter(e){A||"function"!=typeof S||S(e),A&&r.props&&"function"==typeof r.props.onMouseEnter&&r.props.onMouseEnter(e),D&&(x||!O)&&m(D,P,L,{locale:T,priority:!0,bypassPrefetchedCheck:!0})},onTouchStart(e){A||"function"!=typeof k||k(e),A&&r.props&&"function"==typeof r.props.onTouchStart&&r.props.onTouchStart(e),D&&(x||!O)&&m(D,P,L,{locale:T,priority:!0,bypassPrefetchedCheck:!0})}};if(!A||w||"a"===r.type&&!("href"in r.props)){let e=void 0!==T?T:null==N?void 0:N.locale,t=(null==N?void 0:N.isLocaleDomain)&&d.getDomainLocale(L,e,null==N?void 0:N.locales,null==N?void 0:N.domainLocales);z.href=t||f.addBasePath(l.addLocale(L,e,null==N?void 0:N.defaultLocale))}return A?s.default.cloneElement(r,z):s.default.createElement("a",Object.assign({},C,z),n)});t.default=y,("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},9246:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.useIntersection=function(e){let{rootRef:t,rootMargin:n,disabled:l}=e,u=l||!s,[c,h]=r.useState(!1),d=r.useRef(null),f=r.useCallback(e=>{d.current=e},[]);r.useEffect(()=>{if(s){if(u||c)return;let e=d.current;if(e&&e.tagName){let r=function(e,t,n){let{id:r,observer:i,elements:s}=function(e){let t;let n={root:e.root||null,margin:e.rootMargin||""},r=o.find(e=>e.root===n.root&&e.margin===n.margin);if(r&&(t=a.get(r)))return t;let i=new Map,s=new IntersectionObserver(e=>{e.forEach(e=>{let t=i.get(e.target),n=e.isIntersecting||e.intersectionRatio>0;t&&n&&t(n)})},e);return t={id:n,observer:s,elements:i},o.push(n),a.set(n,t),t}(n);return s.set(e,t),i.observe(e),function(){if(s.delete(e),i.unobserve(e),0===s.size){i.disconnect(),a.delete(r);let e=o.findIndex(e=>e.root===r.root&&e.margin===r.margin);e>-1&&o.splice(e,1)}}}(e,e=>e&&h(e),{root:null==t?void 0:t.current,rootMargin:n});return r}}else if(!c){let e=i.requestIdleCallback(()=>h(!0));return()=>i.cancelIdleCallback(e)}},[u,n,t,c,d.current]);let p=r.useCallback(()=>{h(!1)},[]);return[f,c,p]};var r=n(7294),i=n(4686);let s="function"==typeof IntersectionObserver,a=new Map,o=[];("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},2675:function(e,t){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.getImageBlurSvg=function(e){let{widthInt:t,heightInt:n,blurWidth:r,blurHeight:i,blurDataURL:s}=e,a=r||t,o=i||n,l=s.startsWith("data:image/jpeg")?"%3CfeComponentTransfer%3E%3CfeFuncA type='discrete' tableValues='1 1'/%3E%3C/feComponentTransfer%3E%":"";return a&&o?"%3Csvg xmlns='http%3A//www.w3.org/2000/svg' viewBox='0 0 ".concat(a," ").concat(o,"'%3E%3Cfilter id='b' color-interpolation-filters='sRGB'%3E%3CfeGaussianBlur stdDeviation='").concat(r&&i?"1":"20","'/%3E").concat(l,"%3C/filter%3E%3Cimage preserveAspectRatio='none' filter='url(%23b)' x='0' y='0' height='100%25' width='100%25' href='").concat(s,"'/%3E%3C/svg%3E"):"%3Csvg xmlns='http%3A//www.w3.org/2000/svg'%3E%3Cimage style='filter:blur(20px)' x='0' y='0' height='100%25' width='100%25' href='".concat(s,"'/%3E%3C/svg%3E")}},9824:function(e,t){"use strict";function n(e){let{config:t,src:n,width:r,quality:i}=e;return"".concat(t.path,"?url=").concat(encodeURIComponent(n),"&w=").concat(r,"&q=").concat(i||75)}Object.defineProperty(t,"__esModule",{value:!0}),t.default=void 0,n.__next_img_default=!0,t.default=n},4945:function(e,t,n){"use strict";n.r(t),n.d(t,{default:function(){return I}});var r=n(5893);n(4744);var i=n(1664),s=n.n(i),a=n(5675),o=n.n(a),l=n(7294),u=n(2373);function c(){let{user:e,username:t}=(0,l.useContext)(u.S);return(0,r.jsx)("nav",{className:"navbar",children:(0,r.jsxs)("ul",{children:[(0,r.jsx)("li",{children:(0,r.jsx)(s(),{href:"/",children:(0,r.jsx)(o(),{src:"/../public/the_film_circle_logo.png",alt:"The Film Circle logo",width:30,height:30})})}),t&&(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)("li",{children:(0,r.jsx)(s(),{href:"/about",children:(0,r.jsx)("button",{className:"btn-white",children:"About"})})}),(0,r.jsx)("li",{className:"push-left",children:(0,r.jsx)(s(),{href:"/admin",children:(0,r.jsx)("button",{className:"btn-blue",children:"My Job Posts"})})}),(0,r.jsx)("li",{children:(0,r.jsx)(s(),{href:"/".concat(t),children:(0,r.jsx)("img",{src:null==e?void 0:e.photoURL})})})]}),!t&&(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)("li",{className:"push-left",children:(0,r.jsx)(s(),{href:"/about",children:(0,r.jsx)("button",{className:"btn-white",children:"About"})})}),(0,r.jsx)("li",{children:(0,r.jsx)(s(),{href:"/enter",children:(0,r.jsx)("button",{className:"btn-blue",children:"Sign In"})})})]})]})})}var h=n(9008),d=n.n(h);function f(){return(0,r.jsx)(d(),{children:(0,r.jsx)("title",{children:"The Film Circle"})})}function p(){return(0,r.jsx)(r.Fragment,{children:(0,r.jsx)("div",{className:"footer-message",children:(0,r.jsxs)("p",{children:["Support ",(0,r.jsx)("i",{children:"The Film Circle"})," by sharing the platform and/or by donating via my website:"," ",(0,r.jsx)("a",{href:"https://ewenmunro.com/donate",target:"_blank",rel:"noopener noreferrer",children:"ewenmunro.com/donate"})]})})})}var m=n(6501),g=n(8233),y=n(2191);n(4444),n(5816),n(3333),n(8463);/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */var v=function(){return(v=Object.assign||function(e){for(var t,n=1,r=arguments.length;n<r;n++)for(var i in t=arguments[n])Object.prototype.hasOwnProperty.call(t,i)&&(e[i]=t[i]);return e}).apply(this,arguments)},w=function(e){return{loading:null==e,value:e}},_=function(e){var t=e?e():void 0,n=(0,l.useReducer)(function(e,t){switch(t.type){case"error":return v(v({},e),{error:t.error,loading:!1,value:void 0});case"reset":return w(t.defaultValue);case"value":return v(v({},e),{error:void 0,loading:!1,value:t.value});default:return e}},w(t)),r=n[0],i=n[1],s=(0,l.useCallback)(function(){i({type:"reset",defaultValue:e?e():void 0})},[e]),a=(0,l.useCallback)(function(e){i({type:"error",error:e})},[]),o=(0,l.useCallback)(function(e){i({type:"value",value:e})},[]);return(0,l.useMemo)(function(){return{error:r.error,loading:r.loading,reset:s,setError:a,setValue:o,value:r.value}},[r.error,r.loading,s,a,o,r.value])},b=function(e,t){var n=_(function(){return e.currentUser}),r=n.error,i=n.loading,s=n.setError,a=n.setValue,o=n.value;return(0,l.useEffect)(function(){var n=(0,y.v)(e,function(e){var n,r,i,o;return n=void 0,r=void 0,i=void 0,o=function(){return function(e,t){var n,r,i,s,a={label:0,sent:function(){if(1&i[0])throw i[1];return i[1]},trys:[],ops:[]};return s={next:o(0),throw:o(1),return:o(2)},"function"==typeof Symbol&&(s[Symbol.iterator]=function(){return this}),s;function o(s){return function(o){return function(s){if(n)throw TypeError("Generator is already executing.");for(;a;)try{if(n=1,r&&(i=2&s[0]?r.return:s[0]?r.throw||((i=r.return)&&i.call(r),0):r.next)&&!(i=i.call(r,s[1])).done)return i;switch(r=0,i&&(s=[2&s[0],i.value]),s[0]){case 0:case 1:i=s;break;case 4:return a.label++,{value:s[1],done:!1};case 5:a.label++,r=s[1],s=[0];continue;case 7:s=a.ops.pop(),a.trys.pop();continue;default:if(!(i=(i=a.trys).length>0&&i[i.length-1])&&(6===s[0]||2===s[0])){a=0;continue}if(3===s[0]&&(!i||s[1]>i[0]&&s[1]<i[3])){a.label=s[1];break}if(6===s[0]&&a.label<i[1]){a.label=i[1],i=s;break}if(i&&a.label<i[2]){a.label=i[2],a.ops.push(s);break}i[2]&&a.ops.pop(),a.trys.pop();continue}s=t.call(e,a)}catch(e){s=[6,e],r=0}finally{n=i=0}if(5&s[0])throw s[1];return{value:s[0]?s[1]:void 0,done:!0}}([s,o])}}}(this,function(n){switch(n.label){case 0:if(!(null==t?void 0:t.onUserChanged))return[3,4];n.label=1;case 1:return n.trys.push([1,3,,4]),[4,t.onUserChanged(e)];case 2:return n.sent(),[3,4];case 3:return s(n.sent()),[3,4];case 4:return a(e),[2]}})},new(i||(i=Promise))(function(e,t){function s(e){try{l(o.next(e))}catch(e){t(e)}}function a(e){try{l(o.throw(e))}catch(e){t(e)}}function l(t){var n;t.done?e(t.value):((n=t.value)instanceof i?n:new i(function(e){e(n)})).then(s,a)}l((o=o.apply(n,r||[])).next())})},s);return function(){n()}},[e]),[o,i,r]};function I(e){let{Component:t,pageProps:n}=e,i=function(){let[e]=b(g.I8),[t,n]=(0,l.useState)(null);return(0,l.useEffect)(()=>{let t;if(e){let r=g.RZ.collection("users").doc(e.uid);t=r.onSnapshot(e=>{var t;n(null===(t=e.data())||void 0===t?void 0:t.username)})}else n(null);return t},[e]),{user:e,username:t}}();return(0,r.jsxs)(u.S.Provider,{value:i,children:[(0,r.jsx)(f,{}),(0,r.jsx)(c,{}),(0,r.jsx)(t,{...n}),(0,r.jsx)(m.x7,{}),(0,r.jsx)("div",{className:"extra-space"}),(0,r.jsx)(p,{})]})}},4744:function(){},7663:function(e){!function(){var t={229:function(e){var t,n,r,i=e.exports={};function s(){throw Error("setTimeout has not been defined")}function a(){throw Error("clearTimeout has not been defined")}function o(e){if(t===setTimeout)return setTimeout(e,0);if((t===s||!t)&&setTimeout)return t=setTimeout,setTimeout(e,0);try{return t(e,0)}catch(n){try{return t.call(null,e,0)}catch(n){return t.call(this,e,0)}}}!function(){try{t="function"==typeof setTimeout?setTimeout:s}catch(e){t=s}try{n="function"==typeof clearTimeout?clearTimeout:a}catch(e){n=a}}();var l=[],u=!1,c=-1;function h(){u&&r&&(u=!1,r.length?l=r.concat(l):c=-1,l.length&&d())}function d(){if(!u){var e=o(h);u=!0;for(var t=l.length;t;){for(r=l,l=[];++c<t;)r&&r[c].run();c=-1,t=l.length}r=null,u=!1,function(e){if(n===clearTimeout)return clearTimeout(e);if((n===a||!n)&&clearTimeout)return n=clearTimeout,clearTimeout(e);try{n(e)}catch(t){try{return n.call(null,e)}catch(t){return n.call(this,e)}}}(e)}}function f(e,t){this.fun=e,this.array=t}function p(){}i.nextTick=function(e){var t=Array(arguments.length-1);if(arguments.length>1)for(var n=1;n<arguments.length;n++)t[n-1]=arguments[n];l.push(new f(e,t)),1!==l.length||u||o(d)},f.prototype.run=function(){this.fun.apply(null,this.array)},i.title="browser",i.browser=!0,i.env={},i.argv=[],i.version="",i.versions={},i.on=p,i.addListener=p,i.once=p,i.off=p,i.removeListener=p,i.removeAllListeners=p,i.emit=p,i.prependListener=p,i.prependOnceListener=p,i.listeners=function(e){return[]},i.binding=function(e){throw Error("process.binding is not supported")},i.cwd=function(){return"/"},i.chdir=function(e){throw Error("process.chdir is not supported")},i.umask=function(){return 0}}},n={};function r(e){var i=n[e];if(void 0!==i)return i.exports;var s=n[e]={exports:{}},a=!0;try{t[e](s,s.exports,r),a=!1}finally{a&&delete n[e]}return s.exports}r.ab="//";var i=r(229);e.exports=i}()},9008:function(e,t,n){e.exports=n(3121)},5675:function(e,t,n){e.exports=n(9749)},1664:function(e,t,n){e.exports=n(1551)},5816:function(e,t,n){"use strict";let r,i;n.r(t),n.d(t,{FirebaseError:function(){return l.ZR},SDK_VERSION:function(){return F},_DEFAULT_ENTRY_NAME:function(){return k},_addComponent:function(){return N},_addOrOverwriteComponent:function(){return R},_apps:function(){return C},_clearComponents:function(){return L},_components:function(){return x},_getProvider:function(){return O},_registerComponent:function(){return D},_removeServiceInstance:function(){return P},deleteApp:function(){return j},getApp:function(){return q},getApps:function(){return B},initializeApp:function(){return V},onLog:function(){return $},registerVersion:function(){return z},setLogLevel:function(){return G}});var s,a=n(8463),o=n(3333),l=n(4444);let u=(e,t)=>t.some(t=>e instanceof t),c=new WeakMap,h=new WeakMap,d=new WeakMap,f=new WeakMap,p=new WeakMap,m={get(e,t,n){if(e instanceof IDBTransaction){if("done"===t)return h.get(e);if("objectStoreNames"===t)return e.objectStoreNames||d.get(e);if("store"===t)return n.objectStoreNames[1]?void 0:n.objectStore(n.objectStoreNames[0])}return g(e[t])},set:(e,t,n)=>(e[t]=n,!0),has:(e,t)=>e instanceof IDBTransaction&&("done"===t||"store"===t)||t in e};function g(e){var t;if(e instanceof IDBRequest)return function(e){let t=new Promise((t,n)=>{let r=()=>{e.removeEventListener("success",i),e.removeEventListener("error",s)},i=()=>{t(g(e.result)),r()},s=()=>{n(e.error),r()};e.addEventListener("success",i),e.addEventListener("error",s)});return t.then(t=>{t instanceof IDBCursor&&c.set(t,e)}).catch(()=>{}),p.set(t,e),t}(e);if(f.has(e))return f.get(e);let n="function"==typeof(t=e)?t!==IDBDatabase.prototype.transaction||"objectStoreNames"in IDBTransaction.prototype?(i||(i=[IDBCursor.prototype.advance,IDBCursor.prototype.continue,IDBCursor.prototype.continuePrimaryKey])).includes(t)?function(...e){return t.apply(y(this),e),g(c.get(this))}:function(...e){return g(t.apply(y(this),e))}:function(e,...n){let r=t.call(y(this),e,...n);return d.set(r,e.sort?e.sort():[e]),g(r)}:(t instanceof IDBTransaction&&function(e){if(h.has(e))return;let t=new Promise((t,n)=>{let r=()=>{e.removeEventListener("complete",i),e.removeEventListener("error",s),e.removeEventListener("abort",s)},i=()=>{t(),r()},s=()=>{n(e.error||new DOMException("AbortError","AbortError")),r()};e.addEventListener("complete",i),e.addEventListener("error",s),e.addEventListener("abort",s)});h.set(e,t)}(t),u(t,r||(r=[IDBDatabase,IDBObjectStore,IDBIndex,IDBCursor,IDBTransaction])))?new Proxy(t,m):t;return n!==e&&(f.set(e,n),p.set(n,e)),n}let y=e=>p.get(e),v=["get","getKey","getAll","getAllKeys","count"],w=["put","add","delete","clear"],_=new Map;function b(e,t){if(!(e instanceof IDBDatabase&&!(t in e)&&"string"==typeof t))return;if(_.get(t))return _.get(t);let n=t.replace(/FromIndex$/,""),r=t!==n,i=w.includes(n);if(!(n in(r?IDBIndex:IDBObjectStore).prototype)||!(i||v.includes(n)))return;let s=async function(e,...t){let s=this.transaction(e,i?"readwrite":"readonly"),a=s.store;return r&&(a=a.index(t.shift())),(await Promise.all([a[n](...t),i&&s.done]))[0]};return _.set(t,s),s}m={...s=m,get:(e,t,n)=>b(e,t)||s.get(e,t,n),has:(e,t)=>!!b(e,t)||s.has(e,t)};/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class I{constructor(e){this.container=e}getPlatformInfoString(){let e=this.container.getProviders();return e.map(e=>{if(!function(e){let t=e.getComponent();return(null==t?void 0:t.type)==="VERSION"}(e))return null;{let t=e.getImmediate();return`${t.library}/${t.version}`}}).filter(e=>e).join(" ")}}let T="@firebase/app",E="0.9.3",S=new o.Yd("@firebase/app"),k="[DEFAULT]",A={[T]:"fire-core","@firebase/app-compat":"fire-core-compat","@firebase/analytics":"fire-analytics","@firebase/analytics-compat":"fire-analytics-compat","@firebase/app-check":"fire-app-check","@firebase/app-check-compat":"fire-app-check-compat","@firebase/auth":"fire-auth","@firebase/auth-compat":"fire-auth-compat","@firebase/database":"fire-rtdb","@firebase/database-compat":"fire-rtdb-compat","@firebase/functions":"fire-fn","@firebase/functions-compat":"fire-fn-compat","@firebase/installations":"fire-iid","@firebase/installations-compat":"fire-iid-compat","@firebase/messaging":"fire-fcm","@firebase/messaging-compat":"fire-fcm-compat","@firebase/performance":"fire-perf","@firebase/performance-compat":"fire-perf-compat","@firebase/remote-config":"fire-rc","@firebase/remote-config-compat":"fire-rc-compat","@firebase/storage":"fire-gcs","@firebase/storage-compat":"fire-gcs-compat","@firebase/firestore":"fire-fst","@firebase/firestore-compat":"fire-fst-compat","fire-js":"fire-js",firebase:"fire-js-all"},C=new Map,x=new Map;function N(e,t){try{e.container.addComponent(t)}catch(n){S.debug(`Component ${t.name} failed to register with FirebaseApp ${e.name}`,n)}}function R(e,t){e.container.addOrOverwriteComponent(t)}function D(e){let t=e.name;if(x.has(t))return S.debug(`There were multiple attempts to register component ${t}.`),!1;for(let n of(x.set(t,e),C.values()))N(n,e);return!0}function O(e,t){let n=e.container.getProvider("heartbeat").getImmediate({optional:!0});return n&&n.triggerHeartbeat(),e.container.getProvider(t)}function P(e,t,n=k){O(e,t).clearInstance(n)}function L(){x.clear()}let M=new l.LL("app","Firebase",{"no-app":"No Firebase App '{$appName}' has been created - call Firebase App.initializeApp()","bad-app-name":"Illegal App name: '{$appName}","duplicate-app":"Firebase App named '{$appName}' already exists with different options or config","app-deleted":"Firebase App named '{$appName}' already deleted","no-options":"Need to provide options, when not being deployed to hosting via source.","invalid-app-argument":"firebase.{$appName}() takes either no argument or a Firebase App instance.","invalid-log-argument":"First argument to `onLog` must be null or a function.","idb-open":"Error thrown when opening IndexedDB. Original error: {$originalErrorMessage}.","idb-get":"Error thrown when reading from IndexedDB. Original error: {$originalErrorMessage}.","idb-set":"Error thrown when writing to IndexedDB. Original error: {$originalErrorMessage}.","idb-delete":"Error thrown when deleting from IndexedDB. Original error: {$originalErrorMessage}."});/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class U{constructor(e,t,n){this._isDeleted=!1,this._options=Object.assign({},e),this._config=Object.assign({},t),this._name=t.name,this._automaticDataCollectionEnabled=t.automaticDataCollectionEnabled,this._container=n,this.container.addComponent(new a.wA("app",()=>this,"PUBLIC"))}get automaticDataCollectionEnabled(){return this.checkDestroyed(),this._automaticDataCollectionEnabled}set automaticDataCollectionEnabled(e){this.checkDestroyed(),this._automaticDataCollectionEnabled=e}get name(){return this.checkDestroyed(),this._name}get options(){return this.checkDestroyed(),this._options}get config(){return this.checkDestroyed(),this._config}get container(){return this._container}get isDeleted(){return this._isDeleted}set isDeleted(e){this._isDeleted=e}checkDestroyed(){if(this.isDeleted)throw M.create("app-deleted",{appName:this._name})}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let F="9.17.1";function V(e,t={}){let n=e;if("object"!=typeof t){let e=t;t={name:e}}let r=Object.assign({name:k,automaticDataCollectionEnabled:!1},t),i=r.name;if("string"!=typeof i||!i)throw M.create("bad-app-name",{appName:String(i)});if(n||(n=(0,l.aH)()),!n)throw M.create("no-options");let s=C.get(i);if(s){if((0,l.vZ)(n,s.options)&&(0,l.vZ)(r,s.config))return s;throw M.create("duplicate-app",{appName:i})}let o=new a.H0(i);for(let e of x.values())o.addComponent(e);let u=new U(n,r,o);return C.set(i,u),u}function q(e=k){let t=C.get(e);if(!t&&e===k)return V();if(!t)throw M.create("no-app",{appName:e});return t}function B(){return Array.from(C.values())}async function j(e){let t=e.name;C.has(t)&&(C.delete(t),await Promise.all(e.container.getProviders().map(e=>e.delete())),e.isDeleted=!0)}function z(e,t,n){var r;let i=null!==(r=A[e])&&void 0!==r?r:e;n&&(i+=`-${n}`);let s=i.match(/\s|\//),o=t.match(/\s|\//);if(s||o){let e=[`Unable to register library "${i}" with version "${t}":`];s&&e.push(`library name "${i}" contains illegal characters (whitespace or "/")`),s&&o&&e.push("and"),o&&e.push(`version name "${t}" contains illegal characters (whitespace or "/")`),S.warn(e.join(" "));return}D(new a.wA(`${i}-version`,()=>({library:i,version:t}),"VERSION"))}function $(e,t){if(null!==e&&"function"!=typeof e)throw M.create("invalid-log-argument");(0,o.Am)(e,t)}function G(e){(0,o.Ub)(e)}let K="firebase-heartbeat-store",W=null;function H(){return W||(W=(function(e,t,{blocked:n,upgrade:r,blocking:i,terminated:s}={}){let a=indexedDB.open(e,1),o=g(a);return r&&a.addEventListener("upgradeneeded",e=>{r(g(a.result),e.oldVersion,e.newVersion,g(a.transaction))}),n&&a.addEventListener("blocked",()=>n()),o.then(e=>{s&&e.addEventListener("close",()=>s()),i&&e.addEventListener("versionchange",()=>i())}).catch(()=>{}),o})("firebase-heartbeat-database",0,{upgrade:(e,t)=>{0===t&&e.createObjectStore(K)}}).catch(e=>{throw M.create("idb-open",{originalErrorMessage:e.message})})),W}async function Q(e){try{let t=await H();return t.transaction(K).objectStore(K).get(X(e))}catch(e){if(e instanceof l.ZR)S.warn(e.message);else{let t=M.create("idb-get",{originalErrorMessage:null==e?void 0:e.message});S.warn(t.message)}}}async function Y(e,t){try{let n=await H(),r=n.transaction(K,"readwrite"),i=r.objectStore(K);return await i.put(t,X(e)),r.done}catch(e){if(e instanceof l.ZR)S.warn(e.message);else{let t=M.create("idb-set",{originalErrorMessage:null==e?void 0:e.message});S.warn(t.message)}}}function X(e){return`${e.name}!${e.options.appId}`}class J{constructor(e){this.container=e,this._heartbeatsCache=null;let t=this.container.getProvider("app").getImmediate();this._storage=new ee(t),this._heartbeatsCachePromise=this._storage.read().then(e=>(this._heartbeatsCache=e,e))}async triggerHeartbeat(){let e=this.container.getProvider("platform-logger").getImmediate(),t=e.getPlatformInfoString(),n=Z();return(null===this._heartbeatsCache&&(this._heartbeatsCache=await this._heartbeatsCachePromise),this._heartbeatsCache.lastSentHeartbeatDate===n||this._heartbeatsCache.heartbeats.some(e=>e.date===n))?void 0:(this._heartbeatsCache.heartbeats.push({date:n,agent:t}),this._heartbeatsCache.heartbeats=this._heartbeatsCache.heartbeats.filter(e=>{let t=new Date(e.date).valueOf(),n=Date.now();return n-t<=2592e6}),this._storage.overwrite(this._heartbeatsCache))}async getHeartbeatsHeader(){if(null===this._heartbeatsCache&&await this._heartbeatsCachePromise,null===this._heartbeatsCache||0===this._heartbeatsCache.heartbeats.length)return"";let e=Z(),{heartbeatsToSend:t,unsentEntries:n}=function(e,t=1024){let n=[],r=e.slice();for(let i of e){let e=n.find(e=>e.agent===i.agent);if(e){if(e.dates.push(i.date),et(n)>t){e.dates.pop();break}}else if(n.push({agent:i.agent,dates:[i.date]}),et(n)>t){n.pop();break}r=r.slice(1)}return{heartbeatsToSend:n,unsentEntries:r}}(this._heartbeatsCache.heartbeats),r=(0,l.L)(JSON.stringify({version:2,heartbeats:t}));return this._heartbeatsCache.lastSentHeartbeatDate=e,n.length>0?(this._heartbeatsCache.heartbeats=n,await this._storage.overwrite(this._heartbeatsCache)):(this._heartbeatsCache.heartbeats=[],this._storage.overwrite(this._heartbeatsCache)),r}}function Z(){let e=new Date;return e.toISOString().substring(0,10)}class ee{constructor(e){this.app=e,this._canUseIndexedDBPromise=this.runIndexedDBEnvironmentCheck()}async runIndexedDBEnvironmentCheck(){return!!(0,l.hl)()&&(0,l.eu)().then(()=>!0).catch(()=>!1)}async read(){let e=await this._canUseIndexedDBPromise;if(!e)return{heartbeats:[]};{let e=await Q(this.app);return e||{heartbeats:[]}}}async overwrite(e){var t;let n=await this._canUseIndexedDBPromise;if(n){let n=await this.read();return Y(this.app,{lastSentHeartbeatDate:null!==(t=e.lastSentHeartbeatDate)&&void 0!==t?t:n.lastSentHeartbeatDate,heartbeats:e.heartbeats})}}async add(e){var t;let n=await this._canUseIndexedDBPromise;if(n){let n=await this.read();return Y(this.app,{lastSentHeartbeatDate:null!==(t=e.lastSentHeartbeatDate)&&void 0!==t?t:n.lastSentHeartbeatDate,heartbeats:[...n.heartbeats,...e.heartbeats]})}}}function et(e){return(0,l.L)(JSON.stringify({version:2,heartbeats:e})).length}D(new a.wA("platform-logger",e=>new I(e),"PRIVATE")),D(new a.wA("heartbeat",e=>new J(e),"PRIVATE")),z(T,E,""),z(T,E,"esm2017"),z("fire-js","")},8463:function(e,t,n){"use strict";n.d(t,{H0:function(){return o},wA:function(){return i}});var r=n(4444);class i{constructor(e,t,n){this.name=e,this.instanceFactory=t,this.type=n,this.multipleInstances=!1,this.serviceProps={},this.instantiationMode="LAZY",this.onInstanceCreated=null}setInstantiationMode(e){return this.instantiationMode=e,this}setMultipleInstances(e){return this.multipleInstances=e,this}setServiceProps(e){return this.serviceProps=e,this}setInstanceCreatedCallback(e){return this.onInstanceCreated=e,this}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let s="[DEFAULT]";/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class a{constructor(e,t){this.name=e,this.container=t,this.component=null,this.instances=new Map,this.instancesDeferred=new Map,this.instancesOptions=new Map,this.onInitCallbacks=new Map}get(e){let t=this.normalizeInstanceIdentifier(e);if(!this.instancesDeferred.has(t)){let e=new r.BH;if(this.instancesDeferred.set(t,e),this.isInitialized(t)||this.shouldAutoInitialize())try{let n=this.getOrInitializeService({instanceIdentifier:t});n&&e.resolve(n)}catch(e){}}return this.instancesDeferred.get(t).promise}getImmediate(e){var t;let n=this.normalizeInstanceIdentifier(null==e?void 0:e.identifier),r=null!==(t=null==e?void 0:e.optional)&&void 0!==t&&t;if(this.isInitialized(n)||this.shouldAutoInitialize())try{return this.getOrInitializeService({instanceIdentifier:n})}catch(e){if(r)return null;throw e}else{if(r)return null;throw Error(`Service ${this.name} is not available`)}}getComponent(){return this.component}setComponent(e){if(e.name!==this.name)throw Error(`Mismatching Component ${e.name} for Provider ${this.name}.`);if(this.component)throw Error(`Component for ${this.name} has already been provided`);if(this.component=e,this.shouldAutoInitialize()){if("EAGER"===e.instantiationMode)try{this.getOrInitializeService({instanceIdentifier:s})}catch(e){}for(let[e,t]of this.instancesDeferred.entries()){let n=this.normalizeInstanceIdentifier(e);try{let e=this.getOrInitializeService({instanceIdentifier:n});t.resolve(e)}catch(e){}}}}clearInstance(e=s){this.instancesDeferred.delete(e),this.instancesOptions.delete(e),this.instances.delete(e)}async delete(){let e=Array.from(this.instances.values());await Promise.all([...e.filter(e=>"INTERNAL"in e).map(e=>e.INTERNAL.delete()),...e.filter(e=>"_delete"in e).map(e=>e._delete())])}isComponentSet(){return null!=this.component}isInitialized(e=s){return this.instances.has(e)}getOptions(e=s){return this.instancesOptions.get(e)||{}}initialize(e={}){let{options:t={}}=e,n=this.normalizeInstanceIdentifier(e.instanceIdentifier);if(this.isInitialized(n))throw Error(`${this.name}(${n}) has already been initialized`);if(!this.isComponentSet())throw Error(`Component ${this.name} has not been registered yet`);let r=this.getOrInitializeService({instanceIdentifier:n,options:t});for(let[e,t]of this.instancesDeferred.entries()){let i=this.normalizeInstanceIdentifier(e);n===i&&t.resolve(r)}return r}onInit(e,t){var n;let r=this.normalizeInstanceIdentifier(t),i=null!==(n=this.onInitCallbacks.get(r))&&void 0!==n?n:new Set;i.add(e),this.onInitCallbacks.set(r,i);let s=this.instances.get(r);return s&&e(s,r),()=>{i.delete(e)}}invokeOnInitCallbacks(e,t){let n=this.onInitCallbacks.get(t);if(n)for(let r of n)try{r(e,t)}catch(e){}}getOrInitializeService({instanceIdentifier:e,options:t={}}){let n=this.instances.get(e);if(!n&&this.component&&(n=this.component.instanceFactory(this.container,{instanceIdentifier:e===s?void 0:e,options:t}),this.instances.set(e,n),this.instancesOptions.set(e,t),this.invokeOnInitCallbacks(n,e),this.component.onInstanceCreated))try{this.component.onInstanceCreated(this.container,e,n)}catch(e){}return n||null}normalizeInstanceIdentifier(e=s){return this.component?this.component.multipleInstances?e:s:e}shouldAutoInitialize(){return!!this.component&&"EXPLICIT"!==this.component.instantiationMode}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class o{constructor(e){this.name=e,this.providers=new Map}addComponent(e){let t=this.getProvider(e.name);if(t.isComponentSet())throw Error(`Component ${e.name} has already been registered with ${this.name}`);t.setComponent(e)}addOrOverwriteComponent(e){let t=this.getProvider(e.name);t.isComponentSet()&&this.providers.delete(e.name),this.addComponent(e)}getProvider(e){if(this.providers.has(e))return this.providers.get(e);let t=new a(e,this);return this.providers.set(e,t),t}getProviders(){return Array.from(this.providers.values())}}},3333:function(e,t,n){"use strict";var r,i;n.d(t,{Am:function(){return d},Ub:function(){return h},Yd:function(){return c},in:function(){return r}});/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let s=[];(i=r||(r={}))[i.DEBUG=0]="DEBUG",i[i.VERBOSE=1]="VERBOSE",i[i.INFO=2]="INFO",i[i.WARN=3]="WARN",i[i.ERROR=4]="ERROR",i[i.SILENT=5]="SILENT";let a={debug:r.DEBUG,verbose:r.VERBOSE,info:r.INFO,warn:r.WARN,error:r.ERROR,silent:r.SILENT},o=r.INFO,l={[r.DEBUG]:"log",[r.VERBOSE]:"log",[r.INFO]:"info",[r.WARN]:"warn",[r.ERROR]:"error"},u=(e,t,...n)=>{if(t<e.logLevel)return;let r=new Date().toISOString(),i=l[t];if(i)console[i](`[${r}]  ${e.name}:`,...n);else throw Error(`Attempted to log a message with an invalid logType (value: ${t})`)};class c{constructor(e){this.name=e,this._logLevel=o,this._logHandler=u,this._userLogHandler=null,s.push(this)}get logLevel(){return this._logLevel}set logLevel(e){if(!(e in r))throw TypeError(`Invalid value "${e}" assigned to \`logLevel\``);this._logLevel=e}setLogLevel(e){this._logLevel="string"==typeof e?a[e]:e}get logHandler(){return this._logHandler}set logHandler(e){if("function"!=typeof e)throw TypeError("Value assigned to `logHandler` must be a function");this._logHandler=e}get userLogHandler(){return this._userLogHandler}set userLogHandler(e){this._userLogHandler=e}debug(...e){this._userLogHandler&&this._userLogHandler(this,r.DEBUG,...e),this._logHandler(this,r.DEBUG,...e)}log(...e){this._userLogHandler&&this._userLogHandler(this,r.VERBOSE,...e),this._logHandler(this,r.VERBOSE,...e)}info(...e){this._userLogHandler&&this._userLogHandler(this,r.INFO,...e),this._logHandler(this,r.INFO,...e)}warn(...e){this._userLogHandler&&this._userLogHandler(this,r.WARN,...e),this._logHandler(this,r.WARN,...e)}error(...e){this._userLogHandler&&this._userLogHandler(this,r.ERROR,...e),this._logHandler(this,r.ERROR,...e)}}function h(e){s.forEach(t=>{t.setLogLevel(e)})}function d(e,t){for(let n of s){let i=null;t&&t.level&&(i=a[t.level]),null===e?n.userLogHandler=null:n.userLogHandler=(t,n,...s)=>{let a=s.map(e=>{if(null==e)return null;if("string"==typeof e)return e;if("number"==typeof e||"boolean"==typeof e)return e.toString();if(e instanceof Error)return e.message;try{return JSON.stringify(e)}catch(e){return null}}).filter(e=>e).join(" ");n>=(null!=i?i:t.logLevel)&&e({level:r[n].toLowerCase(),message:a,args:s,type:t.name})}}}},6501:function(e,t,n){"use strict";let r,i;n.d(t,{x7:function(){return ei},ZP:function(){return es}});var s,a=n(7294);let o={data:""},l=e=>"object"==typeof window?((e?e.querySelector("#_goober"):window._goober)||Object.assign((e||document.head).appendChild(document.createElement("style")),{innerHTML:" ",id:"_goober"})).firstChild:e||o,u=/(?:([\u0080-\uFFFF\w-%@]+) *:? *([^{;]+?);|([^;}{]*?) *{)|(}\s*)/g,c=/\/\*[^]*?\*\/|  +/g,h=/\n+/g,d=(e,t)=>{let n="",r="",i="";for(let s in e){let a=e[s];"@"==s[0]?"i"==s[1]?n=s+" "+a+";":r+="f"==s[1]?d(a,s):s+"{"+d(a,"k"==s[1]?"":t)+"}":"object"==typeof a?r+=d(a,t?t.replace(/([^,])+/g,e=>s.replace(/(^:.*)|([^,])+/g,t=>/&/.test(t)?t.replace(/&/g,e):e?e+" "+t:t)):s):null!=a&&(s=/^--/.test(s)?s:s.replace(/[A-Z]/g,"-$&").toLowerCase(),i+=d.p?d.p(s,a):s+":"+a+";")}return n+(t&&i?t+"{"+i+"}":i)+r},f={},p=e=>{if("object"==typeof e){let t="";for(let n in e)t+=n+p(e[n]);return t}return e},m=(e,t,n,r,i)=>{var s,a;let o=p(e),l=f[o]||(f[o]=(e=>{let t=0,n=11;for(;t<e.length;)n=101*n+e.charCodeAt(t++)>>>0;return"go"+n})(o));if(!f[l]){let t=o!==e?e:(e=>{let t,n,r=[{}];for(;t=u.exec(e.replace(c,""));)t[4]?r.shift():t[3]?(n=t[3].replace(h," ").trim(),r.unshift(r[0][n]=r[0][n]||{})):r[0][t[1]]=t[2].replace(h," ").trim();return r[0]})(e);f[l]=d(i?{["@keyframes "+l]:t}:t,n?"":"."+l)}let m=n&&f.g?f.g:null;return n&&(f.g=f[l]),s=f[l],a=t,m?a.data=a.data.replace(m,s):-1===a.data.indexOf(s)&&(a.data=r?s+a.data:a.data+s),l},g=(e,t,n)=>e.reduce((e,r,i)=>{let s=t[i];if(s&&s.call){let e=s(n),t=e&&e.props&&e.props.className||/^go/.test(e)&&e;s=t?"."+t:e&&"object"==typeof e?e.props?"":d(e,""):!1===e?"":e}return e+r+(null==s?"":s)},"");function y(e){let t=this||{},n=e.call?e(t.p):e;return m(n.unshift?n.raw?g(n,[].slice.call(arguments,1),t.p):n.reduce((e,n)=>Object.assign(e,n&&n.call?n(t.p):n),{}):n,l(t.target),t.g,t.o,t.k)}y.bind({g:1});let v,w,_,b=y.bind({k:1});function I(e,t){let n=this||{};return function(){let r=arguments;function i(s,a){let o=Object.assign({},s),l=o.className||i.className;n.p=Object.assign({theme:w&&w()},o),n.o=/ *go\d+/.test(l),o.className=y.apply(n,r)+(l?" "+l:""),t&&(o.ref=a);let u=e;return e[0]&&(u=o.as||e,delete o.as),_&&u[0]&&_(o),v(u,o)}return t?t(i):i}}var T=e=>"function"==typeof e,E=(e,t)=>T(e)?e(t):e,S=(r=0,()=>(++r).toString()),k=()=>{if(void 0===i&&"u">typeof window){let e=matchMedia("(prefers-reduced-motion: reduce)");i=!e||e.matches}return i},A=new Map,C=e=>{if(A.has(e))return;let t=setTimeout(()=>{A.delete(e),O({type:4,toastId:e})},1e3);A.set(e,t)},x=e=>{let t=A.get(e);t&&clearTimeout(t)},N=(e,t)=>{switch(t.type){case 0:return{...e,toasts:[t.toast,...e.toasts].slice(0,20)};case 1:return t.toast.id&&x(t.toast.id),{...e,toasts:e.toasts.map(e=>e.id===t.toast.id?{...e,...t.toast}:e)};case 2:let{toast:n}=t;return e.toasts.find(e=>e.id===n.id)?N(e,{type:1,toast:n}):N(e,{type:0,toast:n});case 3:let{toastId:r}=t;return r?C(r):e.toasts.forEach(e=>{C(e.id)}),{...e,toasts:e.toasts.map(e=>e.id===r||void 0===r?{...e,visible:!1}:e)};case 4:return void 0===t.toastId?{...e,toasts:[]}:{...e,toasts:e.toasts.filter(e=>e.id!==t.toastId)};case 5:return{...e,pausedAt:t.time};case 6:let i=t.time-(e.pausedAt||0);return{...e,pausedAt:void 0,toasts:e.toasts.map(e=>({...e,pauseDuration:e.pauseDuration+i}))}}},R=[],D={toasts:[],pausedAt:void 0},O=e=>{D=N(D,e),R.forEach(e=>{e(D)})},P={blank:4e3,error:4e3,success:2e3,loading:1/0,custom:4e3},L=(e={})=>{let[t,n]=(0,a.useState)(D);(0,a.useEffect)(()=>(R.push(n),()=>{let e=R.indexOf(n);e>-1&&R.splice(e,1)}),[t]);let r=t.toasts.map(t=>{var n,r;return{...e,...e[t.type],...t,duration:t.duration||(null==(n=e[t.type])?void 0:n.duration)||(null==e?void 0:e.duration)||P[t.type],style:{...e.style,...null==(r=e[t.type])?void 0:r.style,...t.style}}});return{...t,toasts:r}},M=(e,t="blank",n)=>({createdAt:Date.now(),visible:!0,type:t,ariaProps:{role:"status","aria-live":"polite"},message:e,pauseDuration:0,...n,id:(null==n?void 0:n.id)||S()}),U=e=>(t,n)=>{let r=M(t,e,n);return O({type:2,toast:r}),r.id},F=(e,t)=>U("blank")(e,t);F.error=U("error"),F.success=U("success"),F.loading=U("loading"),F.custom=U("custom"),F.dismiss=e=>{O({type:3,toastId:e})},F.remove=e=>O({type:4,toastId:e}),F.promise=(e,t,n)=>{let r=F.loading(t.loading,{...n,...null==n?void 0:n.loading});return e.then(e=>(F.success(E(t.success,e),{id:r,...n,...null==n?void 0:n.success}),e)).catch(e=>{F.error(E(t.error,e),{id:r,...n,...null==n?void 0:n.error})}),e};var V=(e,t)=>{O({type:1,toast:{id:e,height:t}})},q=()=>{O({type:5,time:Date.now()})},B=e=>{let{toasts:t,pausedAt:n}=L(e);(0,a.useEffect)(()=>{if(n)return;let e=Date.now(),r=t.map(t=>{if(t.duration===1/0)return;let n=(t.duration||0)+t.pauseDuration-(e-t.createdAt);if(n<0){t.visible&&F.dismiss(t.id);return}return setTimeout(()=>F.dismiss(t.id),n)});return()=>{r.forEach(e=>e&&clearTimeout(e))}},[t,n]);let r=(0,a.useCallback)(()=>{n&&O({type:6,time:Date.now()})},[n]),i=(0,a.useCallback)((e,n)=>{let{reverseOrder:r=!1,gutter:i=8,defaultPosition:s}=n||{},a=t.filter(t=>(t.position||s)===(e.position||s)&&t.height),o=a.findIndex(t=>t.id===e.id),l=a.filter((e,t)=>t<o&&e.visible).length;return a.filter(e=>e.visible).slice(...r?[l+1]:[0,l]).reduce((e,t)=>e+(t.height||0)+i,0)},[t]);return{toasts:t,handlers:{updateHeight:V,startPause:q,endPause:r,calculateOffset:i}}},j=I("div")`
  width: 20px;
  opacity: 0;
  height: 20px;
  border-radius: 10px;
  background: ${e=>e.primary||"#ff4b4b"};
  position: relative;
  transform: rotate(45deg);

  animation: ${b`
from {
  transform: scale(0) rotate(45deg);
	opacity: 0;
}
to {
 transform: scale(1) rotate(45deg);
  opacity: 1;
}`} 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275)
    forwards;
  animation-delay: 100ms;

  &:after,
  &:before {
    content: '';
    animation: ${b`
from {
  transform: scale(0);
  opacity: 0;
}
to {
  transform: scale(1);
  opacity: 1;
}`} 0.15s ease-out forwards;
    animation-delay: 150ms;
    position: absolute;
    border-radius: 3px;
    opacity: 0;
    background: ${e=>e.secondary||"#fff"};
    bottom: 9px;
    left: 4px;
    height: 2px;
    width: 12px;
  }

  &:before {
    animation: ${b`
from {
  transform: scale(0) rotate(90deg);
	opacity: 0;
}
to {
  transform: scale(1) rotate(90deg);
	opacity: 1;
}`} 0.15s ease-out forwards;
    animation-delay: 180ms;
    transform: rotate(90deg);
  }
`,z=I("div")`
  width: 12px;
  height: 12px;
  box-sizing: border-box;
  border: 2px solid;
  border-radius: 100%;
  border-color: ${e=>e.secondary||"#e0e0e0"};
  border-right-color: ${e=>e.primary||"#616161"};
  animation: ${b`
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
`} 1s linear infinite;
`,$=I("div")`
  width: 20px;
  opacity: 0;
  height: 20px;
  border-radius: 10px;
  background: ${e=>e.primary||"#61d345"};
  position: relative;
  transform: rotate(45deg);

  animation: ${b`
from {
  transform: scale(0) rotate(45deg);
	opacity: 0;
}
to {
  transform: scale(1) rotate(45deg);
	opacity: 1;
}`} 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275)
    forwards;
  animation-delay: 100ms;
  &:after {
    content: '';
    box-sizing: border-box;
    animation: ${b`
0% {
	height: 0;
	width: 0;
	opacity: 0;
}
40% {
  height: 0;
	width: 6px;
	opacity: 1;
}
100% {
  opacity: 1;
  height: 10px;
}`} 0.2s ease-out forwards;
    opacity: 0;
    animation-delay: 200ms;
    position: absolute;
    border-right: 2px solid;
    border-bottom: 2px solid;
    border-color: ${e=>e.secondary||"#fff"};
    bottom: 6px;
    left: 6px;
    height: 10px;
    width: 6px;
  }
`,G=I("div")`
  position: absolute;
`,K=I("div")`
  position: relative;
  display: flex;
  justify-content: center;
  align-items: center;
  min-width: 20px;
  min-height: 20px;
`,W=I("div")`
  position: relative;
  transform: scale(0.6);
  opacity: 0.4;
  min-width: 20px;
  animation: ${b`
from {
  transform: scale(0.6);
  opacity: 0.4;
}
to {
  transform: scale(1);
  opacity: 1;
}`} 0.3s 0.12s cubic-bezier(0.175, 0.885, 0.32, 1.275)
    forwards;
`,H=({toast:e})=>{let{icon:t,type:n,iconTheme:r}=e;return void 0!==t?"string"==typeof t?a.createElement(W,null,t):t:"blank"===n?null:a.createElement(K,null,a.createElement(z,{...r}),"loading"!==n&&a.createElement(G,null,"error"===n?a.createElement(j,{...r}):a.createElement($,{...r})))},Q=e=>`
0% {transform: translate3d(0,${-200*e}%,0) scale(.6); opacity:.5;}
100% {transform: translate3d(0,0,0) scale(1); opacity:1;}
`,Y=e=>`
0% {transform: translate3d(0,0,-1px) scale(1); opacity:1;}
100% {transform: translate3d(0,${-150*e}%,-1px) scale(.6); opacity:0;}
`,X=I("div")`
  display: flex;
  align-items: center;
  background: #fff;
  color: #363636;
  line-height: 1.3;
  will-change: transform;
  box-shadow: 0 3px 10px rgba(0, 0, 0, 0.1), 0 3px 3px rgba(0, 0, 0, 0.05);
  max-width: 350px;
  pointer-events: auto;
  padding: 8px 10px;
  border-radius: 8px;
`,J=I("div")`
  display: flex;
  justify-content: center;
  margin: 4px 10px;
  color: inherit;
  flex: 1 1 auto;
  white-space: pre-line;
`,Z=(e,t)=>{let n=e.includes("top")?1:-1,[r,i]=k()?["0%{opacity:0;} 100%{opacity:1;}","0%{opacity:1;} 100%{opacity:0;}"]:[Q(n),Y(n)];return{animation:t?`${b(r)} 0.35s cubic-bezier(.21,1.02,.73,1) forwards`:`${b(i)} 0.4s forwards cubic-bezier(.06,.71,.55,1)`}},ee=a.memo(({toast:e,position:t,style:n,children:r})=>{let i=e.height?Z(e.position||t||"top-center",e.visible):{opacity:0},s=a.createElement(H,{toast:e}),o=a.createElement(J,{...e.ariaProps},E(e.message,e));return a.createElement(X,{className:e.className,style:{...i,...n,...e.style}},"function"==typeof r?r({icon:s,message:o}):a.createElement(a.Fragment,null,s,o))});s=a.createElement,d.p=void 0,v=s,w=void 0,_=void 0;var et=({id:e,className:t,style:n,onHeightUpdate:r,children:i})=>{let s=a.useCallback(t=>{if(t){let n=()=>{r(e,t.getBoundingClientRect().height)};n(),new MutationObserver(n).observe(t,{subtree:!0,childList:!0,characterData:!0})}},[e,r]);return a.createElement("div",{ref:s,className:t,style:n},i)},en=(e,t)=>{let n=e.includes("top"),r=e.includes("center")?{justifyContent:"center"}:e.includes("right")?{justifyContent:"flex-end"}:{};return{left:0,right:0,display:"flex",position:"absolute",transition:k()?void 0:"all 230ms cubic-bezier(.21,1.02,.73,1)",transform:`translateY(${t*(n?1:-1)}px)`,...n?{top:0}:{bottom:0},...r}},er=y`
  z-index: 9999;
  > * {
    pointer-events: auto;
  }
`,ei=({reverseOrder:e,position:t="top-center",toastOptions:n,gutter:r,children:i,containerStyle:s,containerClassName:o})=>{let{toasts:l,handlers:u}=B(n);return a.createElement("div",{style:{position:"fixed",zIndex:9999,top:16,left:16,right:16,bottom:16,pointerEvents:"none",...s},className:o,onMouseEnter:u.startPause,onMouseLeave:u.endPause},l.map(n=>{let s=n.position||t,o=en(s,u.calculateOffset(n,{reverseOrder:e,gutter:r,defaultPosition:t}));return a.createElement(et,{id:n.id,key:n.id,onHeightUpdate:u.updateHeight,className:n.visible?er:"",style:o},"custom"===n.type?E(n.message,n):i?i(n):a.createElement(ee,{toast:n,position:s}))}))},es=F}},function(e){var t=function(t){return e(e.s=t)};e.O(0,[774,179],function(){return t(1118),t(880)}),_N_E=e.O()}]);