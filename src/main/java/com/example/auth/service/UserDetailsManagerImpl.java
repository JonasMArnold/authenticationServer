package com.example.auth.service;

import com.example.auth.repository.UserCacheImpl;
import com.example.auth.repository.UserRepository;
import com.example.auth.entity.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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


    /**
     * Adds user to Database.
     * @param user User Object
     */
    @Override
    public void createUser(UserDetails user) {
        Assert.isTrue(!userExists(user.getUsername()), "user should not exist");
        Assert.isInstanceOf(User.class, user);

        User savedUser = this.userRepository.save((User) user);
        this.userCache.put(savedUser);
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

        User savedUser = this.userRepository.save((User) user);
        this.userCache.evict(savedUser.getId());
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

        ((User) user).setPassword(newPassword);

        User savedUser = this.userRepository.save((User) user);
        this.userCache.evict(savedUser.getId());

        return user;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = this.userCache.get(username);

        if (user != null) return user.copy();

        Optional<User> userEntity = this.userRepository.findByUsername(username);

        if (userEntity.isEmpty()) {
            return null;
        }

        return userEntity.get();
    }

    public User loadUserById(UUID id) {
        User user = this.userCache.get(id);

        if (user != null) return user.copy();

        Optional<User> userEntity = this.userRepository.findById(id);

        if (userEntity.isEmpty()) {
            return null;
        }

        return userEntity.get();
    }

    public List<User> getAllUsers() {
        Iterable<User> iter = this.userRepository.findAll();

        //TODO: paging
        return StreamSupport.stream(iter.spliterator(), false).collect(Collectors.toList());
    }

    public UserCacheImpl getUserCache() {
        return this.userCache;
    }
}
