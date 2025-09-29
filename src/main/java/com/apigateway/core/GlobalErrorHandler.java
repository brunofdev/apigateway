package com.apigateway.core;


import com.apigateway.responseapi.ApiError; // Importe suas classes
import com.apigateway.responseapi.ApiResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Component
@Order(-1) // Prioridade alta para sobrescrever o handler de erro padrão do Spring
public class GlobalErrorHandler implements ErrorWebExceptionHandler {

    // ObjectMapper para converter nosso objeto de erro em JSON
    private final ObjectMapper objectMapper;

    public GlobalErrorHandler() {
        this.objectMapper = new ObjectMapper();
        // Adiciona suporte para serializar LocalDateTime
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        ServerHttpResponse response = exchange.getResponse();

        // Se a resposta já foi enviada, não fazemos nada
        if (response.isCommitted()) {
            return Mono.error(ex);
        }

        // Definimos o status e a mensagem padrão
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR; // 500
        String message = "Ocorreu um erro inesperado no servidor.";
        String errorType = "Internal Server Error";

        // Aqui podemos verificar o tipo da exceção para dar respostas mais específicas
        // Por exemplo, um erro de conexão com o serviço interno geralmente resulta em um 502 ou 503
        if (ex instanceof org.springframework.cloud.gateway.support.NotFoundException ||
                ex.getCause() instanceof java.net.ConnectException) {
            status = HttpStatus.BAD_GATEWAY; // 502
            message = "O serviço de destino está indisponível no momento.";
            errorType = "Bad Gateway";
        }

        // Montamos nosso objeto ApiError
        ApiError apiError = new ApiError();
        apiError.setStatus(status.value());
        apiError.setError(errorType);
        apiError.setMessage(message);
        apiError.setTimestamp(LocalDateTime.now());

        // Montamos nossa resposta padrão ApiResponse
        ApiResponse<Object> apiResponse = ApiResponse.error("Erro ao processar a requisição.", apiError);

        // Preparamos a resposta HTTP
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        try {
            // Convertemos nosso ApiResponse para bytes
            byte[] responseBytes = objectMapper.writeValueAsBytes(apiResponse);
            DataBuffer buffer = response.bufferFactory().wrap(responseBytes);
            // Escrevemos a resposta customizada
            return response.writeWith(Mono.just(buffer));
        } catch (JsonProcessingException e) {
            // Em caso de falha na serialização, logamos e retornamos o erro original
            return Mono.error(e);
        }
    }
}