package com.example.auth.dto;

import com.example.auth.constraints.PasswordConstraint;
import com.example.auth.constraints.UsernameConstraint;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.UUID;

@Data
public class UserCreationDto {

    @UsernameConstraint
    private final String username; // unique username, which can be changed

    @PasswordConstraint
    private String password;
    private final UUID id; // unique user id

    @Email
    private final String email;

    @Size(min = 2, max = 32)
    private final String firstName;

    @Size(min = 2, max = 32)
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
