package com.example.auth.config;

import com.example.auth.util.UrlConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "pokermind")
public class AuthorizationServerConfig {

    private boolean sendVerificationMail = true;
    private final String defaultLoginRedirectUrl = UrlConstants.HOME_URL;

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
