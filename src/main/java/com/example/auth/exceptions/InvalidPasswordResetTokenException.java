package com.example.auth.exceptions;

public class InvalidPasswordResetTokenException extends Throwable {

    public InvalidPasswordResetTokenException() {
        super("Invalid password reset token");
    }
}
