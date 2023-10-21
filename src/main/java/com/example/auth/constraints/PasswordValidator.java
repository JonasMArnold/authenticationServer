package com.example.auth.constraints;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;

public class PasswordValidator implements ConstraintValidator<PasswordConstraint, String> {

    @Override
    public void initialize(PasswordConstraint contactNumber) {}

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        HibernateConstraintValidatorContext hibernateContext =
                context.unwrap( HibernateConstraintValidatorContext.class );

        hibernateContext.disableDefaultConstraintViolation();

        if (value == null) return false;

        if (value.length() < 8) {
            hibernateContext
                    .buildConstraintViolationWithTemplate("Password cannot be shorter than 8 characters!")
                    .addConstraintViolation();

            return false;
        }

        if (value.length() > 128) {
            hibernateContext
                    .buildConstraintViolationWithTemplate("Password cannot be longer than 128 characters!")
                    .addConstraintViolation();
            return false;
        }

        if (!value.matches(".*\\d+.*")) {
            hibernateContext
                    .buildConstraintViolationWithTemplate("Password must contain at least one digit!")
                    .addConstraintViolation();
            return false;
        }

        if (!value.matches(".*[A-Z]+.*")) {
            hibernateContext
                    .buildConstraintViolationWithTemplate("Password must contain at least one capital letter!")
                    .addConstraintViolation();
            return false;
        }

        if (!value.matches(".*[a-z]+.*")) {
            hibernateContext
                    .buildConstraintViolationWithTemplate("Password must contain at least one non capital letter!")
                    .addConstraintViolation();
            return false;
        }

        return true;
    }

}