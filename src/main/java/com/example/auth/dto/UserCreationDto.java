package com.example.auth.dto;

import lombok.Data;

import java.util.UUID;

@Data
public class UserCreationDto {

    private final String username; // unique username, which can be changed
    private String password;
    private final UUID id; // unique user id
    private final String email;
    private final String firstName;
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
