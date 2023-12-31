package com.example.auth.service;

import com.example.auth.exceptions.InvalidEmailVerificationTokenException;
import com.example.auth.exceptions.InvalidPasswordResetTokenException;
import com.example.auth.entity.User;
import org.slf4j.Logger;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.slf4j.LoggerFactory.getLogger;


/**
 * Issues and validates opaque token strings used for password resets / email verification.
 */
@Service
public class TokenService {

    private static final Logger logger = getLogger(TokenService.class);

    private final static int TOKEN_LENGTH = 128;

    private final static Duration EMAIL_VERIFICATION_TOKEN_TTL = Duration.ofDays(1);
    private final static Duration PASSWORD_RESET_TOKEN_TTL = Duration.ofMinutes(10);

    private final Map<String, IdentificationToken> passwordResetToken = new HashMap<>();
    private final Map<String, IdentificationToken> verificationToken = new HashMap<>();

    private final SecureRandom sRand = new SecureRandom();

    public TokenService() {}


    /**
     * Creates a token for the password reset link. Saves token data in memory.
     *
     * @param user user
     * @return token
     */
    public String getPasswordResetToken(User user) {
        String token = generateToken();

        logger.trace("Generated password reset token: " + token);

        Instant currentTime = Instant.now();
        this.passwordResetToken.put(token, new IdentificationToken(user.getId(), currentTime.plus(PASSWORD_RESET_TOKEN_TTL)));

        return token;
    }


    /**
     * Creates email verification
     * @param user user
     * @return token
     */
    public String getEmailVerificationToken(User user) {
        String token = generateToken();

        logger.trace("Generated email verification token: " + token);

        Instant currentTime = Instant.now();
        this.verificationToken.put(token, new IdentificationToken(user.getId(), currentTime.plus(EMAIL_VERIFICATION_TOKEN_TTL)));

        return token;
    }


    /**
     * Generates random hex string of length TOKEN_LENGTH
     */
    private String generateToken() {
        byte[] buffer = new byte[TOKEN_LENGTH / 2];
        sRand.nextBytes(buffer);

        //take 4 bits each from each byte to generate a base 16 string of length TOKEN_LENGTH
        StringBuilder tokenBuilder = new StringBuilder();

        for (byte b : buffer) {
            tokenBuilder.append(parseNibble(b & 0b1111));
            tokenBuilder.append(parseNibble((b >> 4) & 0b1111));
        }

        return tokenBuilder.toString();
    }


    /**
     * Parsed lower 4 bits of b to hex digit
     */
    private char parseNibble(int b) {
        if (b < 10) {
            return (char) ('0' + b);
        } else {
            return (char) ('a' + (b - 10));
        }
    }

    /**
     * Verify password reset token and returns user id if token was correct.
     */
    public UUID verifyPasswordResetToken(String token) throws InvalidPasswordResetTokenException {
        if(token.length() != TOKEN_LENGTH) {
            throw new InvalidPasswordResetTokenException();
        }

        if (passwordResetToken.containsKey(token)) {
            IdentificationToken identificationToken = this.passwordResetToken.remove(token);

            Instant currentTime = Instant.now();
            if (currentTime.isBefore(identificationToken.getExpiresAt())) {
                return identificationToken.getUserId();

            } else {
                logger.trace("Password reset token expired.");
            }

        } else {
            logger.trace("Password reset token not found.");
        }

        throw new InvalidPasswordResetTokenException();
    }


    /**
     * Verify email verification token and returns user id if token was correct.
     */
    public UUID verifyEmailVerification(String token) throws InvalidEmailVerificationTokenException {
        if(token.length() != TOKEN_LENGTH) {
            throw new InvalidEmailVerificationTokenException();
        }

        if (verificationToken.containsKey(token)) {
            IdentificationToken identificationToken = this.verificationToken.remove(token);

            Instant currentTime = Instant.now();
            if (currentTime.isBefore(identificationToken.getExpiresAt())) {
                return identificationToken.getUserId();

            } else {
                logger.trace("Email verification token expired.");
            }

        } else {
            logger.trace("Email verification token not found.");
        }

        throw new InvalidEmailVerificationTokenException();
    }


    private record IdentificationToken(UUID userId, Instant expiresAt) {

        public Instant getExpiresAt() {
            return expiresAt;
        }

        public UUID getUserId() {
            return userId;
        }
    }
}
