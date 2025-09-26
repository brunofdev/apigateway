package com.apigateway.filters;

import com.apigateway.jwt.JwtUtil;
import io.jsonwebtoken.Jwt;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final JwtUtil jwtUtil;

    public static final List<String> openApiEndpoints = List.of(
            "/api/auth/login",
            "/api/users/register"
    );

    public AuthenticationFilter(JwtUtil jwtUtil){
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }
    @Override
    public GatewayFilter apply(Config config){
        return (exchange, chain) -> {
            String path = exchange.getRequest().getURI().getPath();
            if (openApiEndpoints.contains(path)){
                return chain.filter(exchange);
            }
            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return this.onError(exchange, "Cabeçalho de autorização ausente ou malformado", HttpStatus.UNAUTHORIZED);
            }
            String token = authHeader.substring(7);

            if(!jwtUtil.isTokenValid(token)){
                return this.onError(exchange, "Token JWT inválido ou expirado", HttpStatus.UNAUTHORIZED);
            }
            String username = jwtUtil.extractUsername(token);
            exchange.getRequest().mutate().header("X-Authenticated-User", username);

            return chain.filter(exchange);
        };
    }
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }

    public static class Config {
        // Classe de configuração vazia, necessária para o AbstractGatewayFilterFactory
    }
}
