package com.bm3.bm3_auth_server.config;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.Collection;
import java.util.List;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        System.out.println("Entró al SecurityFilterChain: " + this.getClass().getSimpleName() + " (authServerSecurityFilterChain)");
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http
                .securityMatcher(
                        "/oauth2/**",
                        "/.well-known/**",
                        "/connect/**",
                        "/userinfo"
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/.well-known/openid-configuration",
                                "/.well-known/jwks.json",
                                "/.well-known/oauth-authorization-server",
                                "/oauth2/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(
                        "/.well-known/**",
                        "/oauth2/**",
                        "/connect/**",
                        "/oidc/**"
                ))
                .with(authorizationServerConfigurer, configurer ->
                        configurer.oidc(Customizer.withDefaults())
                );

        return http
                .formLogin(Customizer.withDefaults())
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        String keyStorePass = "123456";
        String alias        = "auth-key";

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = new ClassPathResource("auth-server.p12").getInputStream()) {
            ks.load(is, keyStorePass.toCharArray());
        }

        RSAKey rsaKey = RSAKey.load(ks, alias, keyStorePass.toCharArray());
        System.out.println("RSAKey cagado: " + rsaKey);
        JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());
        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication principal = context.getPrincipal();
                Collection<? extends GrantedAuthority> auths = principal.getAuthorities();
                List<String> roles = auths.stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList();
                context.getClaims().claim("roles", roles);
            }
        };
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .build();
    }
}