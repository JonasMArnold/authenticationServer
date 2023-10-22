package com.example.auth.constraints;

import com.example.auth.util.ErrorCodeConstants;
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
                    .buildConstraintViolationWithTemplate(String.valueOf(ErrorCodeConstants.PASSWORD_TOO_SHORT))
                    .addConstraintViolation();

            return false;
        }

        if (value.length() > 128) {
            hibernateContext
                    .buildConstraintViolationWithTemplate(String.valueOf(ErrorCodeConstants.PASSWORD_TOO_LONG))
                    .addConstraintViolation();
            return false;
        }

        if (!value.matches(".*\\d+.*")) {
            hibernateContext
                    .buildConstraintViolationWithTemplate(String.valueOf(ErrorCodeConstants.PASSWORD_MUST_CONTAIN_NUMBER))
                    .addConstraintViolation();
            return false;
        }

        if (!value.matches(".*[A-Z]+.*")) {
            hibernateContext
                    .buildConstraintViolationWithTemplate(String.valueOf(ErrorCodeConstants.PASSWORD_MUST_CONTAIN_CAPITAL_LETTER))
                    .addConstraintViolation();
            return false;
        }

        if (!value.matches(".*[a-z]+.*")) {
            hibernateContext
                    .buildConstraintViolationWithTemplate(String.valueOf(ErrorCodeConstants.PASSWORD_MUST_CONTAIN_SPECIAL_CHAR))
                    .addConstraintViolation();
            return false;
        }

        return true;
    }

}