package com.example.auth.controller;

import com.example.auth.dto.UserCreationDto;
import com.example.auth.dto.UserDto;
import com.example.auth.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;

@Controller
public class AuthController {

    private UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
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
    public ResponseEntity<UserDto> createUser(@Valid UserCreationDto user) {
        return ResponseEntity.ok(this.userService.createUser(user));
    }

    /**
     * Custom log in page
     */
    @GetMapping("/login")
    public String oauth2LoginPage(Model model,
                                  @CurrentSecurityContext(expression = "authentication") Authentication authentication,
                                  @Value("${spring.security.oauth2.server.login.captcha.enabled:true}") boolean enableCaptchaLogin,
                                  @RequestAttribute(name = "org.springframework.security.web.csrf.CsrfToken", required = false) CsrfToken csrfToken) {

        if (!(authentication instanceof AnonymousAuthenticationToken)){
            return "already logged in";
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
    public String recoverAccount() {
        return "not implemented";
    }
}
