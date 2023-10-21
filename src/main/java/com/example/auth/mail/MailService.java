package com.example.auth.mail;

import com.example.auth.service.TokenService;
import com.example.auth.user.User;
import com.example.auth.util.UrlConstants;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {

    private static final String SOURCE_ADDRESS = "pokermindgto@gmail.com";

    private final JavaMailSender emailSender;
    private final TokenService tokenService;

    public MailService(JavaMailSender javaMailSender, TokenService tokenService) {
        this.emailSender = javaMailSender;
        this.tokenService = tokenService;
    }


    /**
     * Send an email verification link to the registered email of supplied user.
     *
     * @param user user
     */
    public void sendEmailVerificationMail(User user) {
        String dest = user.getEmail();

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(SOURCE_ADDRESS);
        message.setTo(dest);
        message.setSubject("Verify Email");

        String verificationLink = generateEmailVerificationLink(user);
        message.setText("Click here to verify email: \n" + verificationLink);

        emailSender.send(message);
    }


    /**
     * Send a password reset link to the registered email address of supplied user.
     *
     * @param user user
     */
    public void sendPasswordResetMail(User user) {
        String dest = user.getEmail();

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(SOURCE_ADDRESS);
        message.setTo(dest);
        message.setSubject("Password Reset");

        String resetLink = generatePasswordResetLink(user);
        message.setText("Password reset: \n" + resetLink);
        emailSender.send(message);

    }


    /**
     * Generate password reset token for reset link
     */
    private String generateEmailVerificationLink(User user) {
        String token = this.tokenService.getEmailVerificationToken(user);

        return UrlConstants.AUTH_URL + "/verify?token=" + token;
    }


    /**
     * Generate password reset token for reset link
     */
    private String generatePasswordResetLink(User user) {
        String token = this.tokenService.getPasswordResetToken(user);

        return UrlConstants.AUTH_URL + "/recover/reset?token=" + token;
    }
}
