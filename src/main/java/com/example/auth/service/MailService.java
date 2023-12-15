package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.util.UrlConstants;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.Map;

@Service
public class MailService {

    private static final String SOURCE_ADDRESS = "auth@noreply.com";

    private final TemplateEngine emailTemplateEngine;
    private final JavaMailSender emailSender;
    private final TokenService tokenService;

    public MailService(TemplateEngine emailTemplateEngine,
                       JavaMailSender javaMailSender, TokenService tokenService) {
        this.emailTemplateEngine = emailTemplateEngine;
        this.emailSender = javaMailSender;
        this.tokenService = tokenService;
    }


    /**
     * Send an email verification link to the registered email of supplied user.
     *
     * @param user user
     */
    public void sendEmailVerificationMail(User user) throws MessagingException {
        String dest = user.getEmail();

        MimeMessage message = this.emailSender.createMimeMessage();
        final MimeMessageHelper messageHelper =
                new MimeMessageHelper(message, true, "utf-8");

        messageHelper.setFrom(SOURCE_ADDRESS);
        messageHelper.setTo(dest);
        messageHelper.setSubject("Verify Email");

        String verificationLink = generateEmailVerificationLink(user);

        Context thymeleafContext = new Context();
        thymeleafContext.setVariables(Map.of("verifyLink", verificationLink));
        String mailBody = emailTemplateEngine.process("verify_email.html", thymeleafContext);
        message.setText(mailBody, "utf-8", "html");

        emailSender.send(message);
    }


    /**
     * Send a password reset link to the registered email address of supplied user.
     *
     * @param user user
     */
    public void sendPasswordResetMail(User user) throws MessagingException {
        String dest = user.getEmail();

        MimeMessage message = this.emailSender.createMimeMessage();
        final MimeMessageHelper messageHelper =
                new MimeMessageHelper(message, true, "utf-8");

        messageHelper.setFrom(SOURCE_ADDRESS);
        messageHelper.setTo(dest);
        messageHelper.setSubject("Reset Password");

        String resetLink = generatePasswordResetLink(user);

        Context thymeleafContext = new Context();
        thymeleafContext.setVariables(Map.of("resetLink", resetLink));
        String mailBody = emailTemplateEngine.process("reset_password.html", thymeleafContext);
        message.setText(mailBody, "utf-8", "html");

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
