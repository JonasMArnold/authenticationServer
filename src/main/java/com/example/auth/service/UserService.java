package com.example.auth.service;

import com.example.auth.exceptions.UserCreationException;
import com.example.auth.repository.UserRepository;
import com.example.auth.user.User;
import com.example.auth.dto.UserCreationDto;
import com.example.auth.dto.UserDto;
import com.example.auth.user.UserEntity;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

/**
 * Service for managing user accounts
 */
@Service
public class UserService {

    private UserDetailsManagerImpl userDetailsManager;
    private UserRepository userRepository; // we can abstract this logic (pagination) down to userDetailsManager

    public UserService(UserDetailsManagerImpl userDetailsManager,
                       UserRepository userRepository) {
        this.userDetailsManager = userDetailsManager;
        this.userRepository = userRepository;
    }

    /**
     * Creates user and saves it to the UserDetailsManager
     * @param userCreationDto
     * @return UserCreationSuccessDto
     */
    public UserDto createUser(@Valid UserCreationDto userCreationDto) throws UserCreationException {

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

        if (this.userDetailsManager.userExists(user.getUsername())) {
            throw new UserCreationException("User already exists");
        }

        this.userDetailsManager.createUser(user);

        return new UserDto(user);
    }

    public Page<UserDto> getAllUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(this::convertToUserDto);
    }

    public User getUserById(UUID id) {
        return this.userDetailsManager.loadUserById(id);
    }

    public void deleteUserById(UUID id) {
        String username = this.userDetailsManager.loadUserById(id).getUsername();
        this.userDetailsManager.deleteUser(username);
    }



    private UserDto convertToUserDto(UserEntity userEntity) {
        return new UserDto(userEntity);
    }

}
