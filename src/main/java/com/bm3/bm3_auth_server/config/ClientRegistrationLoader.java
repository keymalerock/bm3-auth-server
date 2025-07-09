package com.bm3.bm3_auth_server.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.UUID;

/*
Class for loading default clients. This bean must be removed afterwards, as it exposes sensitive data.
Author: Erick bonilla
 */
@Configuration
public class ClientRegistrationLoader {
    @Bean
    public CommandLineRunner registerClients(
            RegisteredClientRepository clientRepository,
            PasswordEncoder passwordEncoder
    ) throws SQLException {
        return args -> {
            // Client Machine-to-Machine
            if (clientRepository.findByClientId("bm3_banking") == null) {
                RegisteredClient m2mClient = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("bm3_banking")
                        .clientSecret(passwordEncoder.encode("bankingSecret123"))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .scope("read")
                        .scope("write")
                        .clientName("BM3 Banking Microservice")
                        .build();
                clientRepository.save(m2mClient);
            }

            // Client Frontend (web/app móvil)
            if (clientRepository.findByClientId("bm3_frontend") == null) {
                RegisteredClient frontendClient = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("bm3_frontend")
                        .clientSecret(passwordEncoder.encode("frontendSecret123"))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("https://oauth.pstmn.io/v1/callback") // Cambia esto al redirect real de tu frontend
                        .scope("openid")
                        .scope("profile")
                        .scope("email")
                        .scope("read")
                        .scope("write")
                        .clientName("BM3 Frontend App")
                        .build();
                clientRepository.save(frontendClient);
            }
        };
    }
}