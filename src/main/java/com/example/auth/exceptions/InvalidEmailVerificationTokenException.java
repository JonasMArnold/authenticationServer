package com.example.auth.exceptions;

public class InvalidEmailVerificationTokenException extends Throwable {

    public InvalidEmailVerificationTokenException() {
        super("Invalid email verification token");
    }
}
