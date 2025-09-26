package com.apigateway.filters;

import com.apigateway.jwt.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Objects;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final JwtUtil jwtUtil;

    // Injetamos o segredo interno aqui
    @Value("${API_INTERNAL_SECRET}") // Certifique-se que o nome da variável de ambiente é exatamente este
    private String internalApiSecret;

    // Lista de endpoints que não exigem JWT (são públicos)
    public static final List<String> openApiEndpoints = List.of(
            "/api/auth/login", // Ex: Login de usuário
            "/api/users/register" // Ex: Cadastro de usuário
            // Adicione outras rotas públicas aqui, se houver
    );

    public AuthenticationFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            // Adicionar o header interno para todas as requisições que passam pelo Gateway
            // Isso permite que os serviços internos confiem que a requisição veio do Gateway.
            // O serviço interno pode então decidir se o header secreto é suficiente
            // ou se ele também precisa de um token JWT.
            ServerHttpRequest.Builder mutatedRequest = request.mutate()
                    .header("X-Internal-Secret", internalApiSecret);

            // Verifica se a rota é pública e não requer JWT
            if (openApiEndpoints.contains(path)) {
                // Se for uma rota pública, simplesmente adiciona o header interno
                // e permite que a requisição prossiga.
                return chain.filter(exchange.mutate().request(mutatedRequest.build()).build());
            }

            // Para rotas protegidas, validamos o JWT
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return this.onError(exchange, "Cabeçalho de autorização ausente ou malformado.", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7); // Remove "Bearer "

            try {
                if (!jwtUtil.isTokenValid(token)) {
                    return this.onError(exchange, "Token JWT inválido ou expirado.", HttpStatus.UNAUTHORIZED);
                }

                String username = jwtUtil.extractUsername(token);

                // Adiciona o username extraído do JWT à requisição
                // Isso pode ser útil para serviços internos saberem quem é o usuário logado
                mutatedRequest.header("X-Authenticated-User", username);

            } catch (ExpiredJwtException e) {
                return this.onError(exchange, "Token JWT expirado.", HttpStatus.UNAUTHORIZED);
            } catch (UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
                return this.onError(exchange, "Token JWT inválido.", HttpStatus.UNAUTHORIZED);
            }

            // Continua a cadeia de filtros com a requisição modificada (com headers adicionais)
            return chain.filter(exchange.mutate().request(mutatedRequest.build()).build());
        };
    }

    /**
     * Helper para lidar com erros de autenticação.
     * Define o status da resposta e completa a requisição.
     * Poderia ser mais elaborado para incluir uma mensagem no corpo da resposta.
     *
     * @param exchange O ServerWebExchange atual.
     * @param err A mensagem de erro.
     * @param httpStatus O HttpStatus a ser retornado.
     * @return Um Mono<Void> que completa a resposta.
     */
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        // Opcional: Adicionar a mensagem de erro ao corpo da resposta
        // response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");
        // return response.writeWith(Mono.just(response.bufferFactory().wrap(err.getBytes())));
        return response.setComplete();
    }

    public static class Config {
        // Classe de configuração vazia, necessária para o AbstractGatewayFilterFactory.
        // Pode ser usada para configurar o filtro com propriedades do Spring.
    }
}