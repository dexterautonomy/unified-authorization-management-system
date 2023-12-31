package com.hingebridge.devops.configurations;

import com.hingebridge.devops.configurations.custom_password.CustomPasswordGrantAuthenticationConverter;
import com.hingebridge.devops.configurations.custom_password.CustomAuthenticationProvider;
import com.hingebridge.devops.services.CustomUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService customUserDetailsService;

    private static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\r\n"
            + "MIIEpQIBAAKCAQEA70NMgI76fwPnq+bPyM0fiu1zefobHWnXnVko91EMot9CQl7I\r\n"
            + "M0n13m+Jx30/2lP7mru12ks4SAjQ7KnM3Ew0wKVQ2n93f24IuQIXKE/N4eHxj0W9\r\n"
            + "GvV/HKuPZjNVRq8socEndIq1iimv8aREBEi0Q7Rdmoc3LZ1auel86LQ4a4pUJVrq\r\n"
            + "PRYZYEymrIifO5ccj8Nv0zKYbKifFVA/dk1GRo7SwEi5nSOpfQjcbtjes2SgqQlj\r\n"
            + "8DYjdRuNjKaS70f49nsg4zcAIQ3vAVuFsyt2vhPKduMt2T2/zrM4VlAhY98rBggU\r\n"
            + "6yC3cI4JfOQDDFd1ZxyuotYt0FeHnv4GSSrzSwIDAQABAoIBAHiPgbn50bE0x4Tw\r\n"
            + "Hd1BttYrRhe9dfJBRfssVR8hwOtE8j89QUXOy8xUialyrD0YOlzCnySq6GYrwxKt\r\n"
            + "kOOkpqQ36ODgf9c/G7gVnJOcetKKJk0aR+qQr4dDz1MhJKQkWqn7CSWJS2aeEOEC\r\n"
            + "857w/5xqAwx9e8lJU9EAHQeo4BEXPlq/JwP1R/KgopjAkGSwgBpUz6xr7nixLLB4\r\n"
            + "xn9wg6qYWPbbbN/crpPPQco5DeKaYpcV9u2O4LpWfuAiCb3We6UbWlc93H8S8gPF\r\n"
            + "HZgUubbkNtwDYA1RCVO7JMG80eDMkdh91ikPQrmjnJSiqIEsxkxmFtA8MWLWux+U\r\n"
            + "eIjZA9ECgYEA9630M0YNEIFXNt+gJXuY+aA22GTYOcbaObTWRe0RENAgZL1hi+ES\r\n"
            + "IhemOv4ot6ec5E2VRlzeY3HZKrO7ZKaXcTjIuBrVap/nYwwNuCKZx/fsCtkcSuSV\r\n"
            + "Pj2Bm34I7sv9FbUQwqyg42rxvib72UUWoyDAkNW0QvNnsnOemrGgTQMCgYEA90z2\r\n"
            + "P37R7tUEFC6nbQzJXH06gvC1d2FJmygLd79eV0DlDpCkCAqV/p7iaazSqhNt9NQC\r\n"
            + "1TptRo7J+E/mUjdane5PkM13DUK0Edcnmu8K1dMgDXJFF2bK86hegHEZmDYzyUJd\r\n"
            + "DEgV44D33nZPIlxdNMfFh2Ao/4O7T+BLzHPwehkCgYEAntwpPFXa/VIoUV7fxgrf\r\n"
            + "lITJiMQt1+kOgWLW6KTkhEcp79N0ZJao3csTaNUp4poUTG7ipu3cCia0pun+8NDV\r\n"
            + "Y96LB2LWrfwAGoxZpFg1EIiZEmAtAHBatUAYCFavfhLCspCfPm4hB5zJjzBL6xCg\r\n"
            + "M2NHf95CL4sVYOU9vnTdn2cCgYEA3VjKc6ysdKu/Gd1kSAwQ0zLXQ0n18qNmgXSH\r\n"
            + "RyhHZauVGcNGvlfTR3KoztM8P7RiT6fP3VCNbIDzr8i8K0yWVBNwrffpnjnc+Lbu\r\n"
            + "IRPiS97Lqp1jz/1WnF5QL4CL2xxwn6xBonOG+/l8Ymbcj7HCTzKbz363U3RyHJ1y\r\n"
            + "2s3PKUkCgYEAif9f0K82NcJN0QzuEkLIXLHU7BVkdCfGmz524bPI7gXm6Zlbfhh4\r\n"
            + "lfk1LyfEooaEIYZo8S5Ievp8aheZwfddZDiAyqCYqBjtvVePZ7D/niQR4004k34R\r\n"
            + "4cJ3m3CHzCIGWXjb2asyJwW2D7iOZE+G+apTrq8T37mq4m+t9g6nquA=\r\n" + "-----END RSA PRIVATE KEY-----";

    private static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\r\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA70NMgI76fwPnq+bPyM0f\r\n"
            + "iu1zefobHWnXnVko91EMot9CQl7IM0n13m+Jx30/2lP7mru12ks4SAjQ7KnM3Ew0\r\n"
            + "wKVQ2n93f24IuQIXKE/N4eHxj0W9GvV/HKuPZjNVRq8socEndIq1iimv8aREBEi0\r\n"
            + "Q7Rdmoc3LZ1auel86LQ4a4pUJVrqPRYZYEymrIifO5ccj8Nv0zKYbKifFVA/dk1G\r\n"
            + "Ro7SwEi5nSOpfQjcbtjes2SgqQlj8DYjdRuNjKaS70f49nsg4zcAIQ3vAVuFsyt2\r\n"
            + "vhPKduMt2T2/zrM4VlAhY98rBggU6yC3cI4JfOQDDFd1ZxyuotYt0FeHnv4GSSrz\r\n" + "SwIDAQAB\r\n"
            + "-----END PUBLIC KEY-----";

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient airPayClient = RegisteredClient.withId("airPayClient")
                .clientId("test-client")
                .clientSecret("$2a$10$Kap06i8TyIcJELoy3GKpTepH0kHaWZS0WUv/yCkBe6Z7CJa9t5pmS")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:8080/login/oauth2")
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                .scope(OidcScopes.OPENID)
                .scope("read")
                .scope("write")
                .clientSettings(ClientSettings
                        .builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .build()
                )
                .tokenSettings(TokenSettings
                        .builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(10l))
                        .build()
                )
                .build();

        return new InMemoryRegisteredClientRepository(airPayClient);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults())
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .accessTokenRequestConverter(new CustomPasswordGrantAuthenticationConverter())
                        .authenticationProvider(new CustomAuthenticationProvider(oAuth2AuthorizationService(),
                                tokenGenerator(), customUserDetailsService, passwordEncoder)
                        )
                );

        http
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();
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

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
        NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(tokenCustomizer());

        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            Authentication principal = context.getPrincipal();

            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Set<String> authorities = principal
                        .getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                context
                        .getClaims()
                        .claim("authorities", authorities);
            }

            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                Set<String> authorities = principal
                        .getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                context.getClaims().claim("authorities", authorities);
            }
        };
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }

        return keyPair;
    }
}