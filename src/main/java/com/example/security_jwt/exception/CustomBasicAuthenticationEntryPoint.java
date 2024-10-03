package com.example.security_jwt.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
public class CustomBasicAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        response.setHeader("security-jwt-token-error-reason", "Authentication failed");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());

        // Özelleştirilmiş json dönüş türü oluşturabiliriz.

        String message = (authException !=null) &&
                (authException.getMessage() !=null) ? authException.getMessage() : "Authentication failed";


        Map<String,Object> errorResponse = Map.of(
                "timeStamp", System.currentTimeMillis(),
                "error",HttpStatus.UNAUTHORIZED.getReasonPhrase(),
                "status",HttpStatus.UNAUTHORIZED.value(),
                "message",message,
                "path",request.getRequestURI()
        );

        ObjectMapper objectMapper = new ObjectMapper();
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));

    }
}
