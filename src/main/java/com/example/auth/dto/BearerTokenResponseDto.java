package com.example.auth.dto;


/**
 * Used for testing only. Dto for receiving a bearer token.
 */
public class BearerTokenResponseDto {

    private final String accessToken;
    private final String tokenType;
    private final int expiresIn;

    public BearerTokenResponseDto(String accessToken, String tokenType, int expiresIn) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public int getExpiresIn() {
        return expiresIn;
    }
}
