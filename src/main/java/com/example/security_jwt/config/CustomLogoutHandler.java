package com.example.security_jwt.config;

import com.example.security_jwt.model.Token;
import com.example.security_jwt.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomLogoutHandler implements LogoutHandler {

    private final TokenRepository tokenRepository;

    public CustomLogoutHandler(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;

        if (authHeader == null || !authHeader.startsWith("Bearer")) {
            return;
        }

        jwtToken = authHeader.substring(7);

        Token storedToken = tokenRepository.findByAccessToken(jwtToken).orElse(null);

        assert storedToken != null;
        storedToken.setActive(true);
        tokenRepository.save(storedToken);
    }
}
