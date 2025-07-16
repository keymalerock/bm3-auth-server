package com.bm3.bm3_auth_server.config;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
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
@EnableConfigurationProperties(JwtKeyStoreAppProp.class)
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        System.out.println("✅ Entró al SecurityFilterChain AUTH SERVER");
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        /*** despues de que funciona*/
        http
                .cors(Customizer.withDefaults())
                .securityMatcher(request ->
                        request.getServletPath().startsWith("/oauth2/") ||
                                request.getServletPath().startsWith("/.well-known/")
                        || request.getServletPath().startsWith("/connect/**")
                )
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/**", "/.well-known/**","/oidc/**"))
                .with(authorizationServerConfigurer, configurer -> configurer.oidc(Customizer.withDefaults()))
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(JwtKeyStoreAppProp keyStoreConfig) throws Exception {
        String keyStorePass = keyStoreConfig.getPassword();
        String alias = keyStoreConfig.getAlias();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = new ClassPathResource("auth-server.p12").getInputStream()) {
            ks.load(is, keyStorePass.toCharArray());
        }

        RSAKey rsaKey = RSAKey.load(ks, alias, keyStorePass.toCharArray());
        JWKSet jwkSet = new JWKSet(rsaKey);
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
    public AuthorizationServerSettings authorizationServerSettings(JwtKeyStoreAppProp keyStoreConfig) {
        return AuthorizationServerSettings.builder()
                .issuer(keyStoreConfig.getIssuer())
                .build();
    }
}