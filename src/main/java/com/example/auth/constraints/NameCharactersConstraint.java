package com.example.auth.constraints;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * Validates
 */
@Documented
@Constraint(validatedBy = NameCharactersValidator.class)
@Target( { ElementType.METHOD, ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
public @interface NameCharactersConstraint {

    String message() default "Only letters, whitespace and dashes are allowed.";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}