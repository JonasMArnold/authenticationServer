package com.example.auth.service;

import com.example.auth.PokerUserDetailsManager;
import com.example.auth.User;
import com.example.auth.dto.UserCreationDto;
import com.example.auth.dto.UserCreationSuccessDto;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

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
    public UserCreationSuccessDto createUser(UserCreationDto userCreationDto) {

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

        return new UserCreationSuccessDto(user);
    }
}
