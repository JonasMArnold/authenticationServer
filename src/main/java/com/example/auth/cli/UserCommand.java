package com.example.auth.cli;

import com.example.auth.entity.User;
import com.example.auth.service.UserService;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

import java.time.format.DateTimeFormatter;
import java.util.UUID;

@ShellComponent
public class UserCommand {

    private final UserService userService;

    public UserCommand(UserService userService) {
        this.userService = userService;
    }

    @ShellMethod(key = "user info")
    public String userInfo(String userIdentifier) {
        User user = getUser(userIdentifier);

        if(user == null) {
            return "User not found";
        } else {
            return prettyPrint(user);
        }
    }

    @ShellMethod(key = "user modify")
    public String userModify(String userIdentifier,
                             @ShellOption(value = {"--userName"}) String userName,
                             @ShellOption(value = {"--firstName"}) String firstName,
                             @ShellOption(value = {"--lastName"}) String lastName,
                             @ShellOption(value = {"--email"}) String email,
                             @ShellOption(value = {"--verified"}) Boolean verified,
                             @ShellOption(value = {"--disabled"}) Boolean disabled,
                             @ShellOption(value = {"--locked"}) Boolean locked
                             ) {

        User user = getUser(userIdentifier);

        if(user == null) {
            return "User not found";
        } else {
            if(userName != null) user.setUsername(userName);
            if(firstName != null) user.setFirstName(firstName);
            if(lastName != null) user.setLastName(lastName);
            if(email != null) user.setEmail(email);
            if(verified != null) user.setEmailVerified(verified);
            if(locked != null) user.setEmailVerified(locked);
            if(disabled != null) user.setEmailVerified(disabled);

            this.userService.updateUser(user);
            return "";
        }
    }


    /**
     * Parse user from string. First, the identifier is interpreted as a UUID. If parsing fails, interpret it as a
     * username
     *
     * @param userIdentifier user identifier
     * @return user or null if not found
     */
    private User getUser(String userIdentifier) {
        try {
            // try to parse identifier to a UUID
            UUID id = UUID.fromString(userIdentifier);

            //if parsed successfully, find user by id
            return this.userService.getUserById(id);

        } catch(IllegalArgumentException ignored) {
            // try to find user by username
            return this.userService.getUserByUsername(userIdentifier);
        }
    }

    private String prettyPrint(User user) {
        String s = "";

        s += "Username: " + user.getUsername() + "\n";
        s += "Name: " + user.getFirstName() + " " + user.getLastName() + "\n";
        s += "Email: " + user.getEmail() + "\n";
        s += "UUID: " + user.getId() + "\n";
        s += "Authorities: [" + user.getAuthorities().stream().reduce("", (x, a) -> a + " " + x, String::concat) + "]\n";
        s += "Created on: " + user.getAccountCreationTimeStamp().format(DateTimeFormatter.BASIC_ISO_DATE) + "\n";
        s += "Verified: " + user.isEmailVerified() + "\n";
        s += "Locked: " + user.isAccountLocked() + "\n";
        s += "Disabled: " + user.isAccountDisabled() + "\n";
        if(user.isAccountDisabled()) s += "Disabled on: " + user.getAccountDeletionDeadline().format(DateTimeFormatter.BASIC_ISO_DATE) + "\n";

        return s;
    }
}
