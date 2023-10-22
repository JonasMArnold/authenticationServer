package com.example.auth.constraints;

import com.example.auth.util.ErrorCodeConstants;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;

public class NameCharactersValidator implements ConstraintValidator<NameCharactersConstraint, String> {

    @Override
    public void initialize(NameCharactersConstraint contactNumber) {}

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        HibernateConstraintValidatorContext hibernateContext =
                context.unwrap( HibernateConstraintValidatorContext.class );

        if (value == null) return false;

        hibernateContext.disableDefaultConstraintViolation();

        if (value.length() < 2) {
            hibernateContext
                    .buildConstraintViolationWithTemplate(String.valueOf(ErrorCodeConstants.NAME_TOO_SHORT))
                    .addConstraintViolation();
            return false;
        }

        if (value.length() > 32) {
            hibernateContext
                    .buildConstraintViolationWithTemplate(String.valueOf(ErrorCodeConstants.NAME_TOO_LONG))
                    .addConstraintViolation();
            return false;
        }

        if (!value.matches("^[a-zA-Z-]*$")) {
            hibernateContext
                    .buildConstraintViolationWithTemplate(String.valueOf(ErrorCodeConstants.NAME_CANNOT_CONTAIN_CHAR))
                    .addConstraintViolation();
            return false;
        }

        return true;
    }

}