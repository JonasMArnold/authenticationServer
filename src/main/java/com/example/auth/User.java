package com.example.auth;

import lombok.Getter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

import java.time.LocalDateTime;
import java.util.*;

/**
 * The user object that contains information about the user
 */
@Getter
public class User implements UserDetails, CredentialsContainer {

    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private static final String ENCODER_PREFIX = "{bcrypt}";

    private static final Log logger = LogFactory.getLog(User.class);

    private final String username; // unique username, which can be changed
    private String password;
    private final UUID id; // unique user id
    private final String email;
    private final String firstName;
    private final String lastName;
    private final Set<GrantedAuthority> authorities;

    // Nullable
    private final LocalDateTime accountCreationTimeStamp;

    // true if email has been verified
    private final boolean emailVerified;

    // true if the user disabled their account. Will be automatically deleted after 14 days of inactivity
    private final boolean accountDisabled;

    // Nullable
    private final LocalDateTime accountDisableTimeStamp;

    // true if moderator/admin locked the account of the user, for example because of suspicious activity
    private final boolean accountLocked;


    // minimal constructor
    public User(String username,
                String password,
                String email,
                String firstName,
                String lastName) {

        this(username, password, email, firstName, lastName, UUID.randomUUID(),
                Set.of(), false, false, false, LocalDateTime.now(), null);
    }

    // all args constructor
    public User(String username,
                String password,
                String email,
                String firstName,
                String lastName,
                UUID id,
                Set<GrantedAuthority> authorities,
                boolean accountDisabled,
                boolean accountLocked,
                boolean emailVerified,
                LocalDateTime accountCreationTimeStamp,
                LocalDateTime accountDisableTimeStamp) {

        this.username = username;
        this.password = password;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.id = id;
        this.authorities = authorities;
        this.accountDisabled = accountDisabled;
        this.emailVerified = emailVerified;
        this.accountLocked = accountLocked;
        this.accountCreationTimeStamp = accountCreationTimeStamp;
        this.accountDisableTimeStamp = accountDisableTimeStamp;
    }

    /**
     * Get claims for id token
     * @return map of claims
     */
    public Map<String, String> getClaims() {
        Map<String, String> map = new HashMap<>();
        map.put("uuid", this.id.toString());
        map.put("firstName", this.firstName);
        map.put("lastName", this.lastName);
        map.put("email", this.email);
        map.put("verified", String.valueOf(this.emailVerified));
        map.put("locked", String.valueOf(this.accountLocked));
        map.put("disabled", String.valueOf(this.accountDisabled));
        map.put("created_on", String.valueOf(this.accountCreationTimeStamp));

        return map;
    }

    @Override
    public void eraseCredentials() {
        this.password = null; // removes sensitive data for logging etc.
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // we don't want accounts to expire
    }

    @Override
    public boolean isAccountNonLocked() {
        return !this.isAccountLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // we don't want credentials to expire
    }

    @Override
    public boolean isEnabled() {
        return !this.accountLocked && !this.accountDisabled;
    }

    public User copy() {
        return new User(this.username, this.password, this.email, this.firstName, this.lastName, this.id,
                this.authorities, this.accountDisabled, this.accountLocked, this.emailVerified,
                this.accountCreationTimeStamp, this.accountDisableTimeStamp);
    }

    public void setPassword(String newPassword) { // TODO: do this properly
        this.password = newPassword;
    }

    /**
     * Ensure array iteration order is predictable (as per UserDetails.getAuthorities() contract and SEC-717)
     */
    private static SortedSet<GrantedAuthority> sortAuthorities(Collection<? extends GrantedAuthority> authorities) {
        SortedSet<GrantedAuthority> sortedAuthorities =
                new TreeSet<>(Comparator.comparing(GrantedAuthority::getAuthority));

        if (authorities == null) return sortedAuthorities;

        for (GrantedAuthority grantedAuthority : authorities) {
            Assert.notNull(grantedAuthority, "GrantedAuthority list cannot contain any null elements");
            sortedAuthorities.add(grantedAuthority);
        }

        return sortedAuthorities;
    }

    // ----- hash code and equals should only depend on immutable UUID ------

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return id.equals(user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    // ------ builder ------

    public static UserBuilder builder() {
        return new UserBuilder();
    }

    public static final class UserBuilder {
        private String username;
        private String password;
        private UUID id;
        private String email;
        private String firstName;
        private String lastName;
        private List<GrantedAuthority> authorities;
        private LocalDateTime accountCreationTimeStamp;
        private boolean emailVerified = false;
        private boolean accountDisabled = false;
        private LocalDateTime accountDisableTimeStamp = null;
        private boolean accountLocked = false;

        private UserBuilder() {}


        public UserBuilder username(String username) {
            Assert.notNull(username, "username cannot be null");
            this.username = username;
            return this;
        }

        public UserBuilder id(String id) {
            Assert.notNull(id, "id cannot be null");
            this.id = UUID.fromString(id);
            return this;
        }

        /**
         * Takes plain text password and encrypts it
         *
         * @param password plain text password
         * @return builder
         */
        public UserBuilder password(String password) {
            Assert.notNull(password, "password cannot be null");
            this.password = ENCODER_PREFIX + User.passwordEncoder.encode(password);
            return this;
        }

        public UserBuilder email(String email) {
            Assert.notNull(email, "email cannot be null");
            this.email = email;
            return this;
        }

        public UserBuilder firstName(String firstName) {
            Assert.notNull(firstName, "firstName cannot be null");
            this.firstName = firstName;
            return this;
        }

        public UserBuilder lastName(String lastName) {
            Assert.notNull(lastName, "lastName cannot be null");
            this.lastName = lastName;
            return this;
        }

        public UserBuilder roles(String... roles) {
            List<GrantedAuthority> authorities = new ArrayList<>(roles.length);

            for (String role : roles) {
                Assert.isTrue(role != null, "Role name cannot be empty");
                Assert.isTrue(!role.isEmpty(), "Role name cannot be empty");
                Assert.isTrue(!role.startsWith("ROLE_"),
                        () -> role + " cannot start with ROLE_ (it is automatically added)");
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
            return authorities(authorities);
        }

        public UserBuilder authorities(GrantedAuthority... authorities) {
            Assert.notNull(authorities, "authorities cannot be null");
            return authorities(Arrays.asList(authorities));
        }


        public UserBuilder authorities(Collection<? extends GrantedAuthority> authorities) {
            Assert.notNull(authorities, "authorities cannot be null");
            this.authorities = new ArrayList<>(authorities);
            return this;
        }

        public UserBuilder authorities(String... authorities) {
            Assert.notNull(authorities, "authorities cannot be null");
            return authorities(AuthorityUtils.createAuthorityList(authorities));
        }

        public UserBuilder emailVerified(boolean emailVerified) {
            this.emailVerified = emailVerified;
            return this;
        }

        public UserBuilder accountLocked(boolean accountLocked) {
            this.accountLocked = accountLocked;
            return this;
        }

        public UserBuilder credentialsExpired(LocalDateTime accountDisableTimeStamp) {
            this.accountDisableTimeStamp = accountDisableTimeStamp;
            return this;
        }

        public UserBuilder disabled(boolean accountDisabled) {
            this.accountDisabled = accountDisabled;
            return this;
        }

        public UserDetails build() {
            Assert.notNull(this.username, "Username cannot be null");
            Assert.notNull(this.email, "email cannot be null");
            Assert.notNull(this.firstName, "firstName cannot be null");
            Assert.notNull(this.lastName, "lastName cannot be null");

            if (this.accountCreationTimeStamp == null) this.accountCreationTimeStamp = LocalDateTime.now();
            if (this.id == null) this.id = UUID.randomUUID();

            return new User(this.username, this.password, this.email, this.firstName, this.lastName, this.id,
                    sortAuthorities(this.authorities), this.accountDisabled, this.accountLocked, this.emailVerified,
                    this.accountCreationTimeStamp, this.accountDisableTimeStamp);
        }

    }
}
