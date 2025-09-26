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
    @Value("${api.internal.secret}") // Certifique-se que o nome da variável de ambiente é exatamente este
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

            // Se a rota for pública, a lógica termina aqui.
            if (openApiEndpoints.stream().anyMatch(path::startsWith)) {
                // Construímos uma nova requisição apenas para adicionar o header interno
                ServerHttpRequest mutatedRequest = request.mutate()
                        .header("X-Internal-Secret", internalApiSecret)
                        .build();
                // E passamos a requisição modificada para a cadeia de filtros
                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            }

            // --- Lógica para rotas protegidas ---

            // 1. Pega o header de autorização
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            // 2. Valida se o header existe e tem o formato "Bearer "
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return this.onError(exchange, "Cabeçalho de autorização ausente ou malformado.", HttpStatus.UNAUTHORIZED);
            }

            // 3. Extrai e valida o token
            String token = authHeader.substring(7);
            if (!jwtUtil.isTokenValid(token)) {
                return this.onError(exchange, "Token JWT inválido ou expirado.", HttpStatus.UNAUTHORIZED);
            }

            // 4. Se o token for válido, enriquece a requisição com os headers
            String username = jwtUtil.extractUsername(token);

            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-Authenticated-User", username)
                    .header("X-Internal-Secret", internalApiSecret)
                    .build();

            // 5. Deixa a requisição (agora enriquecida) continuar para o serviço de destino
            return chain.filter(exchange.mutate().request(mutatedRequest).build());
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