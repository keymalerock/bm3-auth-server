package com.bm3.bm3_auth_server.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.*;
import org.springframework.security.crypto.password.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties(JwtKeyStoreAppProp.class)
public class DefaultSecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        System.out.println("Entró al SecurityFilterChain: " + this.getClass().getSimpleName() + " (defaultSecurityFilterChain)");
        http
                .cors(Customizer.withDefaults())
                .securityMatcher(request ->
                        !request.getRequestURI().startsWith("/oauth2/") &&
                                !request.getRequestURI().startsWith("/.well-known/") &&
                                !request.getRequestURI().startsWith("/connect/")
                )
                .authorizeHttpRequests(auth ->
                        auth
                                .requestMatchers("/error", "/login").permitAll()
                                //.requestMatchers("/admin/**").hasRole("ADMIN")
                                .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                .logout(logout -> logout
                        .logoutSuccessUrl("/login") //vuelve a pedir claves
                        .permitAll()
                )
                .httpBasic(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(JwtKeyStoreAppProp keyStoreConfig) {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(keyStoreConfig.getAllowedOrigins());
        configuration.setAllowedMethods(keyStoreConfig.getAllowedMethods());
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true); // si se usan cookies o auth header

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

