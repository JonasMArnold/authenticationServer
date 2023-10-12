package com.example.auth.controller;

import com.example.auth.dto.UserCreationDto;
import com.example.auth.dto.UserDto;
import com.example.auth.exceptions.UserCreationException;
import com.example.auth.service.UserService;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;

import java.util.Iterator;

import static org.slf4j.LoggerFactory.getLogger;

@Controller
public class AuthController {

    private static final Logger logger = getLogger(AuthController.class);
    private static final String SAVED_REQUEST_SESSION_ATTRIBUTE = "SPRING_SECURITY_SAVED_REQUEST";

    private final UserService userService;
    private final String defaultRedirectUrl;

    public AuthController(UserService userService, @Value("${defaultLoginRedirectUrl}")  String defaultRedirectUrl) {
        this.userService = userService;
        this.defaultRedirectUrl = defaultRedirectUrl;
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
    public String customLogin(Model model,
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
     * Users who have forgotten their passwords can send themselves a recovery email here.
     */
    @GetMapping("/recover")
    public ResponseEntity<String> recoverAccount() {
        return ResponseEntity.ok("not implemented");
    }
}
