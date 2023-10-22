package com.example.auth.constraints;

import com.example.auth.util.ErrorCodeConstants;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PasswordValidator.class)
@Target( { ElementType.METHOD, ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
public @interface PasswordConstraint {

    String message() default "" + ErrorCodeConstants.USERNAME_TOO_SHORT;

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}