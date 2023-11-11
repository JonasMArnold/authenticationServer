package com.example.auth.controller;
;
import com.example.auth.dto.UserCreationDto;
import com.example.auth.dto.UserDto;
import com.example.auth.exceptions.UserCreationException;
import com.example.auth.service.UserService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

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
     */
    @GetMapping("users")
    public ResponseEntity<Page<UserDto>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String direction) {

        Page<UserDto> users = userService.getAllUsers(PageRequest.of(page, size, Sort.Direction.fromString(direction), sortBy));
        return ResponseEntity.ok(users);
    }

    /**
     * Returns total number of users
     */
    @GetMapping("users/count")
    public ResponseEntity<Long> countUsers() {
        return ResponseEntity.ok(this.userService.count());
    }


    /**
     * Creates a user in the database with minimal validation
     */
    @PostMapping("users")
    public ResponseEntity<UserDto> createUser(UserCreationDto userCreationDto) throws UserCreationException {
        UserDto userDto = this.userService.createUser(userCreationDto);
        return ResponseEntity.ok(userDto);
    }


    /**
     * Gets user dto by id
     */
    @GetMapping("users/{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable UUID id) {
        UserDto user = new UserDto(this.userService.getUserById(id));
        return ResponseEntity.ok(user);
    }

    /**
     * Fully deletes user from the database by id
     */
    @DeleteMapping("users/{id}")
    public ResponseEntity<String> deleteUserById(@PathVariable UUID id) {
        this.userService.deleteUserById(id);
        return ResponseEntity.ok().build();
    }

}
