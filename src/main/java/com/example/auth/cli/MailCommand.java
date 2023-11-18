package com.example.auth.cli;

import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.service.MailService;
import com.example.auth.service.UserService;
import jakarta.mail.MessagingException;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;

import java.util.UUID;

import static com.example.auth.util.Util.getUser;

@ShellComponent
public class MailCommand {

    private final UserService userService;
    private final UserRepository userRepository;
    private final MailService mailService;


    public MailCommand(UserService userService, UserRepository userRepository, MailService mailService) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.mailService = mailService;
    }


    /**
     * Sends verification mail to User.
     *
     * @param userIdentifier user identifier (user name or id)
     */
    @ShellMethod(key = "mail verify")
    public String sendVerificationMail(String userIdentifier) throws MessagingException {
        User user = getUser(this.userService, userIdentifier);

        if (user == null) {
            return "User not found";
        }

        this.mailService.sendEmailVerificationMail(user);

        return "Sent mail";
    }

    /**
     * Sends password reset mail to User.
     *
     * @param userIdentifier user identifier (user name or id)
     */
    @ShellMethod(key = "mail pwreset")
    public String sendPasswordResetMail(String userIdentifier) throws MessagingException {
        User user = getUser(this.userService, userIdentifier);

        if (user == null) {
            return "User not found";
        }

        this.mailService.sendPasswordResetMail(user);

        return "Sent Mail";
    }
}
