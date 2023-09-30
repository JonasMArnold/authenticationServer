package com.example.auth.exceptions;

import com.example.auth.dto.UserCreationDto;

public class UserCreationException extends Throwable {

    private final UserCreationDto user;

    public UserCreationException(String msg) {
        this(msg, null);
    }

    public UserCreationException(String msg, UserCreationDto user) {
        super(msg);

        this.user = user;
    }

    public UserCreationDto getUser() {
        return user;
    }
}
