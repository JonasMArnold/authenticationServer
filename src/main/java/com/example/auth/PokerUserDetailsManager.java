package com.example.auth;

import com.example.auth.dto.UserDto;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.memory.UserAttribute;
import org.springframework.security.core.userdetails.memory.UserAttributeEditor;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.Assert;

import java.util.*;

/**
 * Placeholder class for user detail managing. Will move to custom jdbc user details manager later
 */
public class PokerUserDetailsManager implements UserDetailsManager, UserDetailsPasswordService {

    protected final Log logger = LogFactory.getLog(getClass());

    private final Map<String, User> users = new HashMap<>();

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();

    private AuthenticationManager authenticationManager;

    public PokerUserDetailsManager() {
    }

    public PokerUserDetailsManager(Collection<UserDetails> users) {
        for (UserDetails user : users) {
            createUser(user);
        }
    }

    public PokerUserDetailsManager(UserDetails... users) {
        for (UserDetails user : users) {
            createUser(user);
        }
    }

    public PokerUserDetailsManager(Properties users) {
        Enumeration<?> names = users.propertyNames();
        UserAttributeEditor editor = new UserAttributeEditor();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            editor.setAsText(users.getProperty(name));
            UserAttribute attr = (UserAttribute) editor.getValue();
            Assert.notNull(attr,
                    () -> "The entry with username '" + name + "' could not be converted to an UserDetails");
            createUser(createUserDetails(name, attr));
        }
    }

    private org.springframework.security.core.userdetails.User createUserDetails(String name, UserAttribute attr) {
        return new org.springframework.security.core.userdetails.User(name, attr.getPassword(), attr.isEnabled(), true, true, true, attr.getAuthorities());
    }

    @Override
    public void createUser(UserDetails user) {
        Assert.isTrue(!userExists(user.getUsername()), "user should not exist");
        Assert.isInstanceOf(User.class, user);
        this.users.put(user.getUsername(), (User) user);
    }

    @Override
    public void deleteUser(String username) {
        this.users.remove(username);
    }

    @Override
    public void updateUser(UserDetails user) {
        Assert.isTrue(userExists(user.getUsername()), "user should exist");
        Assert.isInstanceOf(User.class, user);

        this.users.put(user.getUsername(), (User) user);
    }

    @Override
    public boolean userExists(String username) {
        return this.users.containsKey(username);
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        Authentication currentUser = this.securityContextHolderStrategy.getContext().getAuthentication();
        if (currentUser == null) {
            // This would indicate bad coding somewhere
            throw new AccessDeniedException(
                    "Can't change password as no Authentication object found in context " + "for current user.");
        }
        String username = currentUser.getName();
        this.logger.debug(LogMessage.format("Changing password for user '%s'", username));
        // If an authentication manager has been set, re-authenticate the user with the
        // supplied password.
        if (this.authenticationManager != null) {
            this.logger.debug(LogMessage.format("Reauthenticating user '%s' for password change request.", username));
            this.authenticationManager
                    .authenticate(UsernamePasswordAuthenticationToken.unauthenticated(username, oldPassword));
        }
        else {
            this.logger.debug("No authentication manager set. Password won't be re-checked.");
        }

        User user = this.users.get(username);
        Assert.state(user != null, "Current user doesn't exist in database.");

        user.setPassword(newPassword);
    }

    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        String username = user.getUsername();
        User u = this.users.get(username);
        u.setPassword(newPassword);
        return u;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = this.users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }

        return user.copy();
    }

    public User loadUserById(UUID id) {
        User user = this.users.values()
                .stream()
                .filter(u -> u.getId().equals(id))
                .findAny()
                .orElseThrow(() -> new UsernameNotFoundException("User with id " + id.toString() + " not found"));

        return user.copy();
    }

    public List<User> getAllUsers() {
        return new ArrayList<>(this.users.values());
    }

    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
}
