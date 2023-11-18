package com.example.auth.service;

import com.example.auth.config.AuthorizationServerConfig;
import com.example.auth.exceptions.UserCreationException;
import com.example.auth.repository.UserRepository;
import com.example.auth.entity.User;
import com.example.auth.dto.UserCreationDto;
import com.example.auth.dto.UserDto;
import com.example.auth.util.ErrorCodeConstants;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

/**
 * Service for managing user accounts
 */
@Service
public class UserService {

    private final UserDetailsManagerImpl userDetailsManager;
    private final UserRepository userRepository; // we can abstract this logic (pagination) down to userDetailsManager
    private final MailService mailService;
    private final AuthorizationServerConfig config;

    public UserService(UserDetailsManagerImpl userDetailsManager,
                       UserRepository userRepository,
                       MailService mailService,
                       AuthorizationServerConfig config) {

        this.userDetailsManager = userDetailsManager;
        this.userRepository = userRepository;
        this.mailService = mailService;
        this.config = config;
    }

    /**
     * Creates user and saves it to the UserDetailsManager
     * @return UserCreationSuccessDto
     */
    public UserDto createUser(@Valid UserCreationDto userCreationDto) throws UserCreationException {

        User user = (User) User.builder()
                .username(userCreationDto.getUsername())
                .email(userCreationDto.getEmail())
                .firstName(userCreationDto.getFirstName())
                .lastName(userCreationDto.getLastName())
                .password(userCreationDto.getPassword())
                .roles("USER")
                .build();


        if (this.userDetailsManager.userExists(user.getUsername())) {
            throw new UserCreationException(String.valueOf(ErrorCodeConstants.USERNAME_EXISTS));
        }

        if (this.userDetailsManager.emailExists(user.getEmail())) {
            throw new UserCreationException(String.valueOf(ErrorCodeConstants.EMAIL_EXISTS));
        }

        // send verification mail
        if (this.config.isSendVerificationMail()) {
            try {
                this.mailService.sendEmailVerificationMail(user);

            } catch (MessagingException e) {
                e.printStackTrace();

                throw new UserCreationException("Email error");
            }
        }


        this.userDetailsManager.createUser(user);

        return new UserDto(user);
    }

    /**
     * Updates the user's password. Validates and hashes password.
     *
     * @param user user
     * @param newPassword plain text password
     */
    public void updateUserPassword(User user, String newPassword) {
        this.userDetailsManager.updatePassword(user, newPassword);
    }


    public void updateUser(User user) {
        this.userDetailsManager.updateUser(user);
    }

    /**
     * Sets the users email verification status to the supplied parameter
     * @param user user
     * @param verified is email verified
     */
    public void setVerified(User user, boolean verified) {
        user.setEmailVerified(verified);
        this.userDetailsManager.updateUser(user);
    }


    public Page<UserDto> getAllUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(this::convertToUserDto);
    }

    /**
     * Load user by id. Returns null if user was not found
     * @param id uuid
     * @return user
     */
    public User getUserById(UUID id) {
        return this.userDetailsManager.loadUserById(id);
    }

    /**
     * Load user by username. Returns null if user was not found
     * @param username username
     * @return user
     */
    public User getUserByUsername(String username) { return (User) this.userDetailsManager.loadUserByUsername(username); }

    /**
     * Permanently delete user by id.
     * @param id uuid
     */
    public void deleteUserById(UUID id) {
        String username = this.userDetailsManager.loadUserById(id).getUsername();
        this.userDetailsManager.deleteUser(username);
    }

    /**
     * Sets user disabled with a deletion timeout. If the user does not sign in again within "timeout",
     * the account gets permanently deleted.
     *
     * @param user user
     * @param timeout deletion timeout
     */
    public void disableUser(User user, Duration timeout) {
        user.setAccountDisabled(true, timeout);
        this.userDetailsManager.updateUser(user);
    }

    private UserDto convertToUserDto(User user) {
        return new UserDto(user);
    }

    public long count() {
        return this.userRepository.count();
    }
}
