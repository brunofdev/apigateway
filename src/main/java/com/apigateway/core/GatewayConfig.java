package com.apigateway.core;

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

    @Value("${service.feedback.url")
    String feedbackServiceUrl;

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder){
        return builder.routes()
                .route("auth_service_rout", route -> route.path("api/auth/**").uri(authServiceUrl))
                .route("user_service_route", route -> route.path("/api/users/**").uri(userServiceUrl))
                .route("feedback_service_route", route -> route.path("/api/feedbacks/**").uri(feedbackServiceUrl))
                .build();
    }
}
