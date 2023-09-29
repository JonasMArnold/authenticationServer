package com.example.auth.controller;

import com.example.auth.dto.UserCreationDto;
import com.example.auth.dto.UserDto;
import com.example.auth.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AuthController {

    private UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/register")
    public String register(@ModelAttribute UserCreationDto user, Model model) {
        model.addAttribute("user", user);

        return "register";
    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> createUser(@Valid UserCreationDto user) {
        return ResponseEntity.ok(this.userService.createUser(user));
    }
}
