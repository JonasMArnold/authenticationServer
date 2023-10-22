package com.example.auth.constraints;

import com.example.auth.util.ErrorCodeConstants;
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


        if (value == null) return false;

        hibernateContext.disableDefaultConstraintViolation();

        if (value.length() < 3) {
            hibernateContext
                    .buildConstraintViolationWithTemplate(String.valueOf(ErrorCodeConstants.USERNAME_TOO_SHORT))
                    .addConstraintViolation();
            return false;
        }

        if (value.length() > 16) {
            hibernateContext
                    .buildConstraintViolationWithTemplate(String.valueOf(ErrorCodeConstants.USERNAME_TOO_LONG))
                    .addConstraintViolation();
            return false;
        }

        if (!value.matches("^[a-zA-Z0-9_]*$")) {
            hibernateContext
                    .buildConstraintViolationWithTemplate(String.valueOf(ErrorCodeConstants.USERNAME_BAD_CHAR))
                    .addConstraintViolation();
            return false;
        }

        return true;
    }

}