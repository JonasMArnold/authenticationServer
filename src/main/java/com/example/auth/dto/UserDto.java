package com.example.auth.dto;


import com.example.auth.user.User;
import com.example.auth.user.UserEntity;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class UserDto {

    private final String username;
    private final UUID id;
    private final String email;
    private final String firstName;
    private final String lastName;
    private final boolean emailVerified;
    private final boolean accountDisabled;
    private final boolean accountLocked;
    private final LocalDateTime creationTimeStamp;


    public UserDto(User user) {
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.id = user.getId();
        this.creationTimeStamp = user.getAccountCreationTimeStamp();
        this.emailVerified = user.isEmailVerified();
        this.accountLocked = user.isAccountLocked();
        this.accountDisabled = user.isAccountDisabled();
    }

    public UserDto(UserEntity userEntity) {
        this.username = userEntity.getUsername();
        this.id = userEntity.getId();
        this.email = userEntity.getEmail();
        this.firstName = userEntity.getFirstName();
        this.lastName = userEntity.getLastName();
        this.creationTimeStamp = userEntity.getAccountCreationTimeStamp();
        this.emailVerified = userEntity.isEmailVerified();
        this.accountDisabled = userEntity.isAccountDisabled();
        this.accountLocked = userEntity.isAccountLocked();
    }

}
