package com.example.auth.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.List;

@Configuration
public class ClientConfig {

    private static final Logger logger = LoggerFactory.getLogger(ClientConfig.class);

    @Bean
    RegisteredClientRepository clientRepository() {
        RegisteredClient coreServer = RegisteredClient
                .withId("core-server")
                .clientId("core-server")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .build())

                .clientSecret("{noop}V9JxeKYrB8zLqtgQScesRNoygKCKz143Z59iwrABBG0")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)

                .redirectUri("http://localhost:8080/login/oauth2/code/core-server")
                .redirectUri("http://localhost:8080/index")
                .redirectUri("http://localhost:8083/admin")
                .redirectUri("http://localhost:5173/")
                .redirectUri("http://localhost:5050/")

                .postLogoutRedirectUri("http://localhost:8080/index")

                .scope("openid")
                .scope("profile")

                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(69)).build())
                .build();

        logger.info("Creating clientRepository bean");

        return new InMemoryRegisteredClientRepository(List.of(coreServer));
    }
}
