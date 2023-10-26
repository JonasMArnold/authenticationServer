package com.example.auth.entity;

import com.example.auth.constraints.NameCharactersConstraint;
import com.example.auth.constraints.UsernameConstraint;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

@Setter
@Getter
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
