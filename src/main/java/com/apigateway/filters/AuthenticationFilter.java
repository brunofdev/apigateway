package com.apigateway.filters;

import com.apigateway.enums.UserRole;
import com.apigateway.exceptions.InvalidAuthHeaderException;
import com.apigateway.exceptions.InvalidTokenJwtException;
import com.apigateway.jwt.JwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final JwtUtil jwtUtil;
    @Value("${api.internal.secret}") // Certifique-se que o nome da variável de ambiente é exatamente este
    private String internalApiSecret;

    private Map<String, UserRole> mapRoutesWithRoles = Map.of(
            "/api/users", UserRole.USER
    );



    // Lista de endpoints que não exigem JWT (são públicos)
    public static final List<String> openApiEndpoints = List.of(
            "/api/auth/login", // Ex: Login de usuário
            "/api/users/register" // Ex: Cadastro de usuário
            // Adicione outras rotas públicas aqui, se houver
    );
    public String extractAndCheckFormatTokenFromHeader(String authHeader){
        // 2. Valida se o header existe e tem o formato "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
           throw new InvalidAuthHeaderException("O auth do header enviado na requisição está fora do padrão");
        }
        return authHeader.substring(7);
    }
    public void validateToken(String token){
        if (!jwtUtil.isTokenValid(token)) {
            throw new InvalidTokenJwtException("Token inválido ou expirado");
        }
    }
    public AuthenticationFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            if (request.getMethod() == HttpMethod.OPTIONS) {
                return chain.filter(exchange);
            }
            System.out.println(">>> ROTA ACESSADA NO GATEWAY: " + path);
            // Se a rota for pública, a lógica termina aqui.
            if (openApiEndpoints.stream().anyMatch(path::startsWith)) {
                // Construímos uma nova requisição apenas para adicionar o header interno
                ServerHttpRequest mutatedRequest = request.mutate()
                        .header("X-Internal-Secret", internalApiSecret)
                        .build();
                // E passamos a requisição modificada para a cadeia de filtros
                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            }

            try{
            // ------------- Lógica para rotas protegidas--------------
            // 1. Pega o header de autorização
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            String token = extractAndCheckFormatTokenFromHeader(authHeader);
            // 2. valida o token
            validateToken(token);
            //3. Extrai o Username ea permissão(role)
            String username = jwtUtil.extractUsername(token);
            UserRole userRole = jwtUtil.extractUserRole(token);

            if (path.startsWith("/api/users/getusers") && request.getMethod() == HttpMethod.GET && userRole != UserRole.ADMIN) {
                // Se a condição for verdadeira, o acesso é negado.
                return this.onError(exchange, "Acesso Negado: Requer Permissão de Administrador", HttpStatus.FORBIDDEN);
            }

            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-Authenticated-User-Role", userRole.name())
                    .header("X-Authenticated-User", username)
                    .header("X-Internal-Secret", internalApiSecret)

                    .build();
            // 5. Deixa a requisição (agora enriquecida) continuar para o serviço de destino
            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        }catch (InvalidAuthHeaderException | InvalidTokenJwtException e){
                return this.onError(exchange, e.getMessage(), HttpStatus.UNAUTHORIZED);
            }
        };
    }
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