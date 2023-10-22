package com.example.auth.user;

import com.example.auth.constraints.NameCharactersConstraint;
import com.example.auth.constraints.UsernameConstraint;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NonNull;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

@Data
@Entity
public class UserEntity {

    @Id
    private UUID id;

    @UsernameConstraint
    private String username;

    private String passwordHash;

    @NonNull
    @Email
    private String email;

    @NonNull
    @NameCharactersConstraint
    private String firstName;

    @NonNull
    @NameCharactersConstraint
    private String lastName;

    @ElementCollection
    private Set<String> authorities;

    @Temporal(TemporalType.TIMESTAMP)
    private LocalDateTime accountCreationTimeStamp;

    @Temporal(TemporalType.TIMESTAMP)
    private LocalDateTime accountDisableTimeStamp;

    private boolean emailVerified;

    private boolean accountDisabled;

    private boolean accountLocked;

    public UserEntity() {

    }
}
