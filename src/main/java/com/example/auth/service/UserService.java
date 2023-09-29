package com.example.auth.service;

import com.example.auth.PokerUserDetailsManager;
import com.example.auth.User;
import com.example.auth.dto.UserCreationDto;
import com.example.auth.dto.UserDto;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

/**
 * Service for managing user accounts
 */
@Service
public class UserService {

    private PokerUserDetailsManager userDetailsManager;

    public UserService(@Qualifier("userDetailsService") PokerUserDetailsManager userDetailsManager) {
        this.userDetailsManager = userDetailsManager;
    }

    /**
     * Creates user and saves it to the UserDetailsManager
     * @param userCreationDto
     * @return UserCreationSuccessDto
     */
    public UserDto createUser(UserCreationDto userCreationDto) {

        // Check constraints

        // Check email exists

        // send verification mail

        User user = (User) User.builder()
                .username(userCreationDto.getUsername())
                .email(userCreationDto.getEmail())
                .firstName(userCreationDto.getFirstName())
                .lastName(userCreationDto.getLastName())
                .password(userCreationDto.getPassword())
                .roles("USER")
                .build();

        this.userDetailsManager.createUser(user);

        return new UserDto(user);
    }

    public List<User> getAllUsers() {
        return this.userDetailsManager.getAllUsers();
    }

    public User getUserById(UUID id) {
        return this.userDetailsManager.loadUserById(id);
    }

    public void deleteUserById(UUID id) {
        String username = this.userDetailsManager.loadUserById(id).getUsername();
        this.userDetailsManager.deleteUser(username);
    }
}
