# AuthenticateAPI
# .NET 6.0 - Boilerplate API Tutorial with Email Sign Up, Verification, Authentication & Forgot Password

The boilerplate API allows you to register a user account, login and perform different actions based on your role. The Admin role has full access to manage (add/edit/delete) any account in the system, the User role has access to update/delete their own account. The first account registered is automatically assigned the Admin role and subsequent registrations are assigned the User role.

On registration the API sends a verification email with a token and instructions to the account email address, accounts must be verified before they can authenticate. SMTP settings for email are configured in appsettings.json. If you don't have an SMTP service, for quick testing you can use the fake SMTP service https://ethereal.email/ to create a temporary inbox, just click Create Ethereal Account and copy the SMTP configuration options.

<strong> .NET 6 API has the following endpoints/routes to demonstrate email sign up and verification, authentication and role based autorization, refreshing and revoking tokens, forgot password and reset password, and secure account management routes: </strong>
<ul>
<li>POST /accounts/authenticate - public route that accepts POST requests containing an email and password in the body. On success a JWT access token is returned with basic account details, and an HTTP Only cookie containing a refresh token.</li>

<li>POST /accounts/refresh-token - public route that accepts POST requests containing a cookie with a refresh token. On success a new JWT access token is returned with basic account details, and an HTTP Only cookie containing a new refresh token (see refresh token rotation just below for an explanation).</li>

<li>POST /accounts/revoke-token - secure route that accepts POST requests containing a refresh token either in the request body or in a cookie, if both are present priority is given to the request body. On success the token is revoked and can no longer be used to generate new JWT access tokens.</li>

<li>POST /accounts/register - public route that accepts POST requests containing account registration details. On success the account is registered and a verification email is sent to the email address of the account, accounts must be verified before they can authenticate.</li>

<li>POST /accounts/verify-email - public route that accepts POST requests containing an account verification token. On success the account is verified and can now login.</li>

<li>POST /accounts/forgot-password - public route that accepts POST requests containing an account email address. On success a password reset email is sent to the email address of the account. The email contains a single use reset token that is valid for one day.</li>

<li>POST /accounts/validate-reset-token - public route that accepts POST requests containing a password reset token. A message is returned to indicate if the token is valid or not.</li>

<li>POST /accounts/reset-password - public route that accepts POST requests containing a reset token, password and confirm password. On success the account password is reset.</li>

<li>GET /accounts - secure route restricted to the Admin role that accepts GET requests and returns a list of all the accounts in the application.</li>

<li>POST /accounts - secure route restricted to the Admin role that accepts POST requests containing new account details. On success the account is created and automatically verified.</li>

<li>GET /accounts/{id} - secure route that accepts GET requests and returns the details of the account with the specified id. The Admin role can access any account, the User role can only access their own account.</li>

<li>PUT /accounts/{id} - secure route that accepts PUT requests to update the details of the account with the specified id. The Admin role can update any account including its role, the User role can only update there own account details except for role.</li>

<li>DELETE /accounts/{id} - secure route that accepts DELETE requests to delete the account with the specified id. The Admin role can delete any account, the User role can only delete their own account.</li>
</ul>  
**References:
  - https://jasonwatmore.com/post/2022/02/26/net-6-boilerplate-api-tutorial-with-email-sign-up-verification-authentication-forgot-password#project-structure
