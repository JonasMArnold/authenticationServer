package com.example.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "pokermind")
public class AuthorizationServerConfig {

    private boolean sendVerificationMail;
    private String defaultLoginRedirectUrl;

    // Getter and setter methods

    public boolean isSendVerificationMail() {
        return sendVerificationMail;
    }

    public void setSendVerificationMail(boolean sendVerificationMail) {
        this.sendVerificationMail = sendVerificationMail;
    }

    public String defaultRedirectUrl() {
        return defaultLoginRedirectUrl;
    }
}
