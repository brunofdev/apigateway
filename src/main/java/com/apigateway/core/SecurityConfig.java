package com.apigateway.core;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod; // IMPORTANTE: Adicione este import
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        // AQUI ESTÁ O AJUSTE:
                        // Permite a requisição preflight (OPTIONS) do CORS para todas as rotas
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        // Mantém a regra anterior para permitir que nosso filtro controle o resto
                        .pathMatchers("/**").permitAll()
                );
        return http.build();
    }
}