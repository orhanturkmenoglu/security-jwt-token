package com.example.security_jwt.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;


@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

        response.setHeader("security-jwt-token-denied-error-reason", "Authorization failed");
        response.setStatus(HttpStatus.FORBIDDEN.value());

        // Özelleştirilmiş json dönüş türü oluşturabiliriz.

        String message = (accessDeniedException !=null) &&
                (accessDeniedException.getMessage() !=null) ? accessDeniedException.getMessage() : "Authorization failed";


        Map<String,Object> errorResponse = Map.of(
                "timeStamp", System.currentTimeMillis(),
                "error",HttpStatus.FORBIDDEN.getReasonPhrase(),
                "status",HttpStatus.FORBIDDEN.value(),
                "message",message,
                "path",request.getRequestURI()
        );

        ObjectMapper objectMapper = new ObjectMapper();
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
