package com.example.auth.service;

import com.example.auth.repository.UserCacheImpl;
import com.example.auth.repository.UserRepository;
import com.example.auth.user.User;
import com.example.auth.user.UserEntity;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.Assert;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Implementation of spring's UserDetailsManager. Persists users in Database.
 * Uses caching to speed up loading user from Database multiple times.
 *
 *  Internally converts UserDetail objects to UserEntity objects to persist them with spring JPA.
 */
public class UserDetailsManagerImpl implements UserDetailsManager, UserDetailsPasswordService {

    protected final Log logger = LogFactory.getLog(getClass());

    private final UserRepository userRepository;

    private final UserCacheImpl userCache = new UserCacheImpl();

    public UserDetailsManagerImpl(UserRepository userRepository, Collection<UserDetails> users) {
        this.userRepository = userRepository;
        for (UserDetails user : users) {
            createUser(user);
        }
    }

    public UserDetailsManagerImpl(UserRepository userRepository, UserDetails... users) {
        this.userRepository = userRepository;
        for (UserDetails user : users) {
            createUser(user);
        }
    }

    private UserEntity convertToEntity(User user) {
        UserEntity entity = new UserEntity();

        entity.setUsername(user.getUsername());
        entity.setFirstName(user.getFirstName());
        entity.setLastName(user.getLastName());
        entity.setEmail(user.getEmail());
        entity.setAccountDisabled(user.isAccountDisabled());
        entity.setAuthorities(user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));
        entity.setAccountLocked(user.isAccountLocked());
        entity.setEmailVerified(user.isEmailVerified());
        entity.setId(user.getId());
        entity.setPasswordHash(user.getPassword());

        return entity;
    }

    private User convertToUser(UserEntity userEntity) {
        return new User(
                userEntity.getUsername(),
                userEntity.getEmail(),
                userEntity.getPasswordHash(),
                userEntity.getFirstName(),
                userEntity.getLastName(),
                userEntity.getId(),
                userEntity.getAuthorities().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()),
                userEntity.isAccountDisabled(),
                userEntity.isAccountLocked(),
                userEntity.isEmailVerified(),
                userEntity.getAccountCreationTimeStamp(),
                userEntity.getAccountDisableTimeStamp());
    }

    /**
     * Adds user to Database.
     * @param user User Object
     */
    @Override
    public void createUser(UserDetails user) {
        Assert.isTrue(!userExists(user.getUsername()), "user should not exist");
        Assert.isInstanceOf(User.class, user);

        UserEntity userEntity = convertToEntity((User) user);
        this.userRepository.save(userEntity);
        this.userCache.put((User) user);
    }

    @Override
    public void deleteUser(String username) {
        this.userRepository.deleteByUsername(username);
        this.userCache.evict(username);

    }

    public void deleteUser(UUID id) {
        this.userRepository.deleteById(id);
        this.userCache.evict(id);
    }


    @Override
    public void updateUser(UserDetails user) {
        Assert.isTrue(userExists(user.getUsername()), "user should exist");
        Assert.isInstanceOf(User.class, user);

        UserEntity userEntity = convertToEntity((User) user);
        this.userRepository.save(userEntity);
        this.userCache.evict(((User) user).getId());
    }

    /**
     * Returns true if user exists
     * @param username username
     */
    @Override
    public boolean userExists(String username) {
        if (this.userCache.get(username) != null) {
            return true;
        }

        return this.userRepository.existsByUsername(username);
    }

    /**
     * Returns true if user with email exists
     * @param email email
     */
    public boolean emailExists(String email) {
        return this.userRepository.existsByEmail(email);
    }

    /**
     * Returns true if user exists
     * @param id uuid
     */
    public boolean userExists(UUID id) {
        if (this.userCache.get(id) != null) {
            return true;
        }

        return this.userRepository.existsById(id);
    }

    @Deprecated
    @Override
    public void changePassword(String oldPassword, String newPassword) {}

    /**
     * Updates password hash of stored user. Returns null if username was not found.
     * Otherwise, returns updated User Object.
     *
     * @param user a "User" Object
     * @param newPassword the password hash
     * @return updated "User" Object
     */
    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        Assert.isInstanceOf(User.class, user);
        String username = user.getUsername();

        Optional<UserEntity> u = this.userRepository.findByUsername(username);

        if (u.isEmpty()) {
            logger.debug("Couldn't update password because username was not found");
            return null;
        }

        ((User) user).setPassword(newPassword);
        u.get().setPasswordHash(newPassword);

        this.userCache.evict(((User) user).getId());

        return user;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = this.userCache.get(username);

        if (user != null) return user.copy();

        Optional<UserEntity> userEntity = this.userRepository.findByUsername(username);

        if (userEntity.isEmpty()) {
            return null;
        }

        return convertToUser(userEntity.get());
    }

    public User loadUserById(UUID id) {
        User user = this.userCache.get(id);

        if (user != null) return user.copy();

        Optional<UserEntity> userEntity = this.userRepository.findById(id);

        if (userEntity.isEmpty()) {
            return null;
        }

        return convertToUser(userEntity.get());
    }

    public List<User> getAllUsers() {
        Iterable<UserEntity> iter = this.userRepository.findAll();
        return StreamSupport.stream(iter.spliterator(), false).
                map(this::convertToUser)
                .collect(Collectors.toList());
    }
}
