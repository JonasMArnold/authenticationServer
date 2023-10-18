package com.example.auth.controller;

import com.example.auth.dto.PasswordChangeDto;
import com.example.auth.dto.UserCreationDto;
import com.example.auth.dto.UserDto;
import com.example.auth.exceptions.InvalidPasswordResetTokenException;
import com.example.auth.exceptions.UserCreationException;
import com.example.auth.mail.MailService;
import com.example.auth.service.PasswordResetService;
import com.example.auth.service.UserService;
import com.example.auth.user.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

import static org.slf4j.LoggerFactory.getLogger;

@Controller
public class AuthController {

    private static final Logger logger = getLogger(AuthController.class);
    private static final String SAVED_REQUEST_SESSION_ATTRIBUTE = "SPRING_SECURITY_SAVED_REQUEST";

    private final MailService mailService;
    private final UserService userService;
    private final String defaultRedirectUrl;
    private final PasswordResetService passwordResetService;

    public AuthController(UserService userService, MailService mailService,
                          PasswordResetService passwordResetService, @Value("${defaultLoginRedirectUrl}")  String defaultRedirectUrl) {
        this.userService = userService;
        this.defaultRedirectUrl = defaultRedirectUrl;
        this.mailService = mailService;
        this.passwordResetService = passwordResetService;
    }

    /**
     * Redirect to default redirect URL
     */
    @GetMapping("/")
    public String baseUrl() {
        return "redirect:" + this.defaultRedirectUrl;
    }


    /**
     * The registration page
     */
    @GetMapping("/register")
    public String register(@ModelAttribute UserCreationDto user, Model model) {
        model.addAttribute("user", user);

        return "register";
    }


    /**
     * The registration endpoint that accepts a form and creates a new user if the parameters are valid.
     */
    @PostMapping("/register")
    public ResponseEntity<UserDto> createUser(@Valid UserCreationDto user) throws UserCreationException {
        return ResponseEntity.ok(this.userService.createUser(user));
    }


    /**
     * Custom log in page
     */
    @GetMapping("/login")
    public String login(Model model,
                              @CurrentSecurityContext(expression = "authentication") Authentication authentication,
                              @Value("${spring.security.oauth2.server.login.captcha.enabled:true}") boolean enableCaptchaLogin,
                              @RequestAttribute(name = "org.springframework.security.web.csrf.CsrfToken", required = false) CsrfToken csrfToken,
                              HttpServletRequest request) {

        String redirectUrl;
        HttpSession session = request.getSession();

        try {
            Object savedRequestObject = session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);

            if (savedRequestObject instanceof DefaultSavedRequest savedRequest) {
                redirectUrl = savedRequest.getRedirectUrl();

            } else {
                logger.debug("Session does not contain redirect information");
                redirectUrl = this.defaultRedirectUrl;
            }

        } catch (IllegalStateException e) {
            logger.debug("Invalid session: Session expired");
            redirectUrl = this.defaultRedirectUrl;
        }

        if (!(authentication instanceof AnonymousAuthenticationToken)){
            // already logged in
            return "redirect:" + redirectUrl;
        }

        if (csrfToken != null) {
            model.addAttribute("_csrfToken", csrfToken);
        }

        model.addAttribute("enableCaptchaLogin", enableCaptchaLogin);
        return "login";
    }


    /**
     * Account recovery page
     */
    @GetMapping("/recover")
    public String recoverAccountPage() {
        return "recover";
    }


    /**
     * Accepts a username and checks whether user exists. If user exists, sends password reset mail to users email
     * address.
     */
    @PostMapping("/recover")
    public ResponseEntity<String> sendRecoverMail(String username) {
        User user = userService.getUserByUsername(username);

        if (user == null) {
            logger.trace("Could not find user with name: " + username);

            // TODO: return an ambiguous message about whether the user has been found or not
            return ResponseEntity.ok("user not found");
        }

        mailService.sendPasswordResetMail(user);
        logger.info("sent password reset email to user " + username);

        return ResponseEntity.ok("sent mail");
    }


    /**
     * Password reset page.
     */
    @GetMapping("/recover/reset")
    public String resetPasswordPage(@RequestParam String token, Model model) {
        model.addAttribute("token", token);
        return "reset_password";
    }


    /**
     * Endpoint for password reset link. Accepts a password reset token as a String.
     * If token is valid, redirects to password reset page.
     */
    @PostMapping("/recover/reset")
    public ResponseEntity<String> resetPassword(@Valid PasswordChangeDto passwordChange) throws InvalidPasswordResetTokenException {
        logger.debug("Received password reset request with token: " + passwordChange.getToken());

        UUID userId = passwordResetService.getUserFromTokenString(passwordChange.getToken());
        User user = this.userService.getUserById(userId);

        this.userService.updateUserPassword(user, passwordChange.getNewPassword());

        logger.info("Set new password for user " + user.getUsername());

        return ResponseEntity.ok("reset password");
    }
}
