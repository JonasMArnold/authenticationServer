package com.example.auth.constraints;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

import static com.example.auth.util.ErrorCodeConstants.USERNAME_INVALID;
import static com.example.auth.util.ErrorCodeConstants.USERNAME_TOO_SHORT;

@Documented
@Constraint(validatedBy = UsernameValidator.class)
@Target( { ElementType.METHOD, ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
public @interface UsernameConstraint {

    String message() default "" + USERNAME_INVALID;

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}