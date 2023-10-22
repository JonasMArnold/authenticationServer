package com.example.auth.constraints;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

import static com.example.auth.util.ErrorCodeConstants.NAME_CANNOT_CONTAIN_CHAR;

/**
 * Validates
 */
@Documented
@Constraint(validatedBy = NameCharactersValidator.class)
@Target( { ElementType.METHOD, ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
public @interface NameCharactersConstraint {

    String message() default "" + NAME_CANNOT_CONTAIN_CHAR;

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}