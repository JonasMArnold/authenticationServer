package com.example.auth.constraints;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class NameCharactersValidator implements ConstraintValidator<NameCharactersConstraint, String> {

    @Override
    public void initialize(NameCharactersConstraint contactNumber) {}

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return value.matches("^[a-zA-Z-]*$");
    }

}