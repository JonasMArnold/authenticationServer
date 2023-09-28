<h1> 
    Authentication and Authorization Server
</h1>

<p>
    An authorization server built with spring boot and implements oauth 2.0 + OIDC 1.0 protocols

    User information is persisted in a postgres DB.
    Auth server runs on port 8081.

    openid information endpoint: basurl/.well-known/openid-configuration
    jwk key set: baseurl/oauth2/jwks
    token endpoint: baseurl/oauth2/token
    authorization endpoint: baseurl/oauth2/authorize


</p>