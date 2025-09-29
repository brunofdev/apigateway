package com.apigateway.core;

import com.apigateway.filters.AuthenticationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {

    @Value("${service.auth.url}")
    private String authServiceUrl;

    @Value("${service.user.url}")
    private String userServiceUrl;

    // CORREÇÃO 1: Adicionada a chave de fechamento }
    @Value("${service.feedback.url}")
    private String feedbackServiceUrl;

    @Value("${service.processfeedback.url}")
    private String processfeedbackUrl;

    private final AuthenticationFilter authenticationFilter;

    public GatewayConfig(AuthenticationFilter authenticationFilter) {
        this.authenticationFilter = authenticationFilter;
    }

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // Rota para o Serviço de Autenticação
                .route("auth_service_route", route -> route
                        // CORREÇÃO 2: Adicionada a barra /
                        .path("/api/auth/**")
                        // CORREÇÃO 3: Filtro de autenticação aplicado
                        .filters(f -> f.filter(authenticationFilter.apply(new AuthenticationFilter.Config())))
                        .uri(authServiceUrl))

                // Rota para o Serviço de Usuários
                .route("user_service_route", route -> route
                        .path("/api/users/**")
                        // CORREÇÃO 3: Filtro de autenticação aplicado
                        .filters(f -> f.filter(authenticationFilter.apply(new AuthenticationFilter.Config())))
                        .uri(userServiceUrl))

                // Rota para o Serviço de Feedback
                .route("processfeedback_service_route", route -> route
                        .path("/api/processfeedback/**")
                        // CORREÇÃO 3: Filtro de autenticação aplicado
                        .filters(f -> f.filter(authenticationFilter.apply(new AuthenticationFilter.Config())))
                        .uri(processfeedbackUrl))
                .build();
    }
}