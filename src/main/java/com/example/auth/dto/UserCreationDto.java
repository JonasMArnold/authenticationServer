package com.example.auth.dto;

import com.example.auth.constraints.NameCharactersConstraint;
import com.example.auth.constraints.PasswordConstraint;
import com.example.auth.constraints.UsernameConstraint;
import com.example.auth.util.ErrorCodeConstants;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NonNull;

import java.util.UUID;

@Data
public class UserCreationDto {

    @UsernameConstraint
    private final String username; // unique username, which can be changed

    @PasswordConstraint
    private String password;
    private final UUID id; // unique user id

    @NonNull
    @Email(message = "" + ErrorCodeConstants.EMAIL_INVALID)
    private final String email;

    @NonNull
    @NameCharactersConstraint
    private final String firstName;

    @NonNull
    @NameCharactersConstraint
    private final String lastName;


    // all args constructor
    public UserCreationDto(String username,
                String password,
                String email,
                String firstName,
                String lastName,
                UUID id) {

        this.username = username;
        this.password = password;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.id = id;
    }

}
