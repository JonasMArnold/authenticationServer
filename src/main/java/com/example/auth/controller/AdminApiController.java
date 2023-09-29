package com.example.auth.controller;
;
import com.example.auth.dto.UserCreationDto;
import com.example.auth.dto.UserDto;
import com.example.auth.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Admin API for managing users
 */
@RestController
@RequestMapping("/admin")
public class AdminApiController {

    private final UserService userService;

    public AdminApiController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Returns a list of all Users in the database
     * @return
     */
    @GetMapping("users")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        var users = this.userService.getAllUsers();
        List<UserDto> userDtos = users.stream().map(UserDto::new).collect(Collectors.toList());
        return ResponseEntity.ok(userDtos);
    }


    /**
     * Creates a user in the database with minimal validation
     * @param userCreationDto
     * @return
     */
    @PostMapping("users")
    public ResponseEntity<UserDto> createUser(UserCreationDto userCreationDto) {
        UserDto userDto = this.userService.createUser(userCreationDto);
        return ResponseEntity.ok(userDto);
    }


    /**
     * Gets user dto by id
     * @param id
     * @return
     */
    @GetMapping("users/{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable UUID id) {
        UserDto user = new UserDto(this.userService.getUserById(id));
        return ResponseEntity.ok(user);
    }

    /**
     * Fully deletes user from the database by id
     * @param id
     * @return
     */
    @DeleteMapping("users/{id}")
    public ResponseEntity<String> deleteUserById(@PathVariable UUID id) {
        this.userService.deleteUserById(id);
        return ResponseEntity.ok().build();
    }

}
