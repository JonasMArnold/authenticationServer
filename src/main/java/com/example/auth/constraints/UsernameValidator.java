package com.example.auth.constraints;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;

public class UsernameValidator implements ConstraintValidator<UsernameConstraint, String> {

    @Override
    public void initialize(UsernameConstraint contactNumber) {}

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        HibernateConstraintValidatorContext hibernateContext =
                context.unwrap( HibernateConstraintValidatorContext.class );

        hibernateContext.disableDefaultConstraintViolation();

        if (value == null) return false;

        if (value.length() < 3) {
            hibernateContext
                    .buildConstraintViolationWithTemplate("Username must be at least 3 characters long!")
                    .addConstraintViolation();
            return false;
        }

        if (value.length() > 16) {
            hibernateContext
                    .buildConstraintViolationWithTemplate("Username cannot be longer than 16 characters!")
                    .addConstraintViolation();
            return false;
        }

        if (!value.matches("^[a-zA-Z0-9_]*$")) {
            hibernateContext
                    .buildConstraintViolationWithTemplate("Username can only contain letters, numbers and underscores!")
                    .addConstraintViolation();
            return false;
        }

        return true;
    }

}