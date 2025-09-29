package com.apigateway.core;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class CorsConfig {

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();

        // Define as origens permitidas
        corsConfig.setAllowedOrigins(Arrays.asList(
                "http://localhost:5173",
                "https://www.brunofragadev.com"
        ));

        // Permite credenciais (cookies, headers de autenticação)
        corsConfig.setAllowCredentials(true);

        // Define os métodos HTTP permitidos
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // Permite todos os cabeçalhos
        corsConfig.setAllowedHeaders(Arrays.asList("*"));

        // Define o tempo de cache do CORS (1 hora)
        corsConfig.setMaxAge(3600L);

        // Aplica a configuração a todos os endpoints
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return new CorsWebFilter(source);
    }
}