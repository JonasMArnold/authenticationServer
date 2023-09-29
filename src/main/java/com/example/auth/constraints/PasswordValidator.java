package com.example.auth.constraints;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordValidator implements ConstraintValidator<PasswordConstraint, String> {

    @Override
    public void initialize(PasswordConstraint contactNumber) {}

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value.length() < 8) {
            context.buildConstraintViolationWithTemplate("Password must be at least 8 characters long!");
            return false;
        }

        if (value.length() > 128) {
            context.buildConstraintViolationWithTemplate("Password cannot be longer than 128 characters!");
            return false;
        }

        if (!value.matches(".*\\d+.*")) {
            context.buildConstraintViolationWithTemplate("Password must contain at least one digit!");
            return false;
        }

        if (!value.matches(".*[A-Z]+.*")) {
            context.buildConstraintViolationWithTemplate("Password must contain at least one capital letter!");
            return false;
        }

        if (!value.matches(".*[a-z]+.*")) {
            context.buildConstraintViolationWithTemplate("Password must contain at least one non capital letter!");
            return false;
        }

        return true;
    }

}