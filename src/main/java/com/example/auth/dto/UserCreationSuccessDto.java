package com.example.auth.dto;


import com.example.auth.User;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class UserCreationSuccessDto {

    private final String username;
    private final UUID id;
    private final String email;
    private final String firstName;
    private final String lastName;
    private final LocalDateTime creationTimeStamp;


    public UserCreationSuccessDto(User user) {
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.id = user.getId();
        this.creationTimeStamp = user.getAccountCreationTimeStamp();
    }

}
