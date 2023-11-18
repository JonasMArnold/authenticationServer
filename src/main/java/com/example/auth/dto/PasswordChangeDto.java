package com.example.auth.dto;

import com.example.auth.constraints.PasswordConstraint;

import java.util.Objects;


/**
 * Used to receive a "new password" request. Stores a plain text password and an opaque token.
 */
public class PasswordChangeDto {

    private final String token;

    @PasswordConstraint
    private final String newPassword;

    public PasswordChangeDto(String token, String newPassword) {
        this.token = token;
        this.newPassword = Objects.requireNonNullElse(newPassword, "");
    }

    public String getToken() {
        return token;
    }

    public String getNewPassword() {
        return newPassword;
    }
}
