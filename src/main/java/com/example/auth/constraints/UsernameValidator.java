package com.example.auth.constraints;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class UsernameValidator implements ConstraintValidator<UsernameConstraint, String> {

    @Override
    public void initialize(UsernameConstraint contactNumber) {}

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) return false;

        if (value.length() < 3) {
            context.buildConstraintViolationWithTemplate("Username must be at least 3 characters long!");
            return false;
        }

        if (value.length() > 16) {
            context.buildConstraintViolationWithTemplate("Username cannot be longer than 16 characters!");
            return false;
        }

        if (!value.matches("^[a-zA-Z0-9_]*$")) {
            context.buildConstraintViolationWithTemplate("Username can only contain letters, numbers and underscores!");
            return false;
        }

        return true;
    }

}