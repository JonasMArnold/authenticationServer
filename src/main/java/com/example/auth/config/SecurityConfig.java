package com.example.auth.config;

import com.example.auth.repository.UserRepository;
import com.example.auth.service.UserDetailsManagerImpl;
import com.example.auth.user.User;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNullApi;
import org.springframework.lang.Nullable;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String ROLES_CLAIM = "user-authorities";
    private static final String SCOPES_CLAIM = "scope";

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    @Order(1)
    public CorsFilter corsFilter() {

        logger.info("Creating corsFilter bean");


        return new CorsFilter(corsConfigurationSource());
    }

    @Bean(name="corsConfigurationSource")
    CorsConfigurationSource corsConfigurationSource() {

        logger.info("Creating corsConfigurationSource bean");


        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(
                "http://localhost:5173",
                "http://192.168.2.144:5173"
        ));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "Accept",
                "Origin",
                "X-Requested-With"
        ));
        configuration.setExposedHeaders(List.of(
                "Cache-Control",
                "Content-Language",
                "Content-Type",
                "Expires",
                "Last-Modified",
                "Pragma"
        ));
        configuration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    @Order(2)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        logger.info("Creating authorizationServerSecurityFilterChain bean");

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .registeredClientRepository(clientRepository())
                .oidc(Customizer.withDefaults());

        http.exceptionHandling((exceptions) -> exceptions
            .defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        );

        http.oauth2ResourceServer((resourceServer) -> resourceServer
                .jwt(Customizer.withDefaults()));

        http.csrf(AbstractHttpConfigurer::disable);



        return http.build();
    }


    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher(new NegatedRequestMatcher(new AntPathRequestMatcher("/admin/**")));

        logger.info("Creating defaultSecurityFilterChain bean");

        http.authorizeHttpRequests((authorize) ->
                authorize
                        .requestMatchers(new AntPathRequestMatcher("/register")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/recover")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/error/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/css/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/js/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/favicon.ico")).permitAll()
                        .anyRequest().authenticated());

        http.oauth2ResourceServer((resourceServer) -> resourceServer
                .jwt(Customizer.withDefaults()));

        // set custom login form
        http.formLogin(form -> {
            form.loginPage("/login");
            form.permitAll();
        });

        http.logout(conf -> {
            // default logout url
            conf.logoutSuccessHandler(logoutSuccessHandler());
        });

        // Temp disable CSRF
        http.csrf(AbstractHttpConfigurer::disable);
        http.cors(AbstractHttpConfigurer::disable);

        return http.build();
    }


    @Bean
    @Order(4)
    public SecurityFilterChain adminResourceFilterChain(HttpSecurity http) throws Exception {

        // handle out custom endpoints in this filter chain
        http.authorizeHttpRequests((authorize) ->
                authorize
                        .requestMatchers(new AntPathRequestMatcher("/admin/**")).hasRole("ADMIN")
                        .anyRequest().authenticated());

        http.sessionManagement(conf -> conf.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.oauth2ResourceServer((resourceServer) -> resourceServer
                .jwt(Customizer.withDefaults()));

        // Temp disable CSRF
        http.csrf(AbstractHttpConfigurer::disable);
        http.cors(AbstractHttpConfigurer::disable);


        return http.build();
    }


    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        var grantedAuthoritiesConverter = new Converter<Jwt, Collection<GrantedAuthority>>() {

            @Override
            public Collection<GrantedAuthority> convert(@Nullable Jwt source) {
                if (source == null) {
                    return Collections.emptySet();
                }

                return parseRolesFromJwt(source);
            }
        };

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }


    private Collection<GrantedAuthority> parseRolesFromJwt(Jwt jwt) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        var claims = jwt.getClaims();

        if (claims.get(ROLES_CLAIM) instanceof List rolesList) {
            for (Object role : rolesList) {
                if (role instanceof String roleString) {
                    GrantedAuthority authority = new SimpleGrantedAuthority(roleString);
                    authorities.add(authority);
                }
            }
        }


        if (claims.get(SCOPES_CLAIM) instanceof List rolesList) {
            for (Object role : rolesList) {
                if (role instanceof String roleString) {
                    GrantedAuthority authority = new SimpleGrantedAuthority(roleString);
                    authorities.add(authority);
                }
            }
        }

        return authorities;
    }

    /**
     * Logout success handler. Called after /logout endpoint is called. Handles redirect after logout.
     * @return handler
     */
    LogoutSuccessHandler logoutSuccessHandler() {
        SimpleUrlLogoutSuccessHandler handler = new SimpleUrlLogoutSuccessHandler();
        handler.setTargetUrlParameter("redirect_url");
        handler.setDefaultTargetUrl("http://localhost:8080/index");

        return handler;
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(UserDetailsService userDetailsService) {
        return context -> {
            if (context.getTokenType() == OAuth2TokenType.ACCESS_TOKEN) {

                // add user roles to access token

                Authentication principal = context.getPrincipal();
                Set<String> authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                context.getClaims().claim(ROLES_CLAIM, authorities);

            } else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                UserDetails userInfo = userDetailsService.loadUserByUsername(context.getPrincipal().getName());

                // add custom claims to ID token

                if (userInfo instanceof User user) {
                    context.getClaims().claims(claims ->
                            claims.putAll(user.getClaims()));
                }
            }
        };
    }

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

        return new InMemoryRegisteredClientRepository(List.of(coreServer));
    }

    @Bean
    public UserDetailsManagerImpl userDetailsService(UserRepository userRepository) {

        // temporary test users

        UserDetails devAdmin = User.builder()
                .username("dev_admin")
                .email("dev@admin.com")
                .firstName("max")
                .lastName("mustermann")
                .password("devpass")
                .roles("USER", "ADMIN")
                .build();

        UserDetails dev = User.builder()
                .username("dev")
                .email("dev@dev.com")
                .firstName("ben")
                .lastName("dover")
                .password("devpass")
                .roles("USER")
                .build();

        return new UserDetailsManagerImpl(userRepository, devAdmin, dev);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

}