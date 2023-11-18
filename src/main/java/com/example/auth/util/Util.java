package com.example.auth.util;

import com.example.auth.entity.User;
import com.example.auth.service.UserService;

import java.util.UUID;

public class Util {

    /**
     * Parse user from string. First, the identifier is interpreted as a UUID. If parsing fails, interpret it as a
     * username
     *
     * @param userIdentifier user identifier
     * @return user or null if not found
     */
    public static User getUser(UserService userService, String userIdentifier) {
        try {
            // try to parse identifier to a UUID
            UUID id = UUID.fromString(userIdentifier);

            //if parsed successfully, find user by id
            return userService.getUserById(id);

        } catch(IllegalArgumentException ignored) {
            // try to find user by username
            return userService.getUserByUsername(userIdentifier);
        }
    }

}
