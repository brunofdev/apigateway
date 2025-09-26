package com.apigateway.core;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable) // <-- A LINHA MÁGICA QUE RESOLVE O 403
                .authorizeExchange(exchange -> exchange
                        // Por enquanto, vamos permitir todas as requisições para que nosso
                        // filtro customizado (AuthenticationFilter) tenha total controle.
                        .pathMatchers("/**").permitAll()
                );
        return http.build();
    }
}