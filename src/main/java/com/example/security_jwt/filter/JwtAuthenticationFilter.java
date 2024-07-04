package com.example.security_jwt.filter;

import com.example.security_jwt.repository.TokenRepository;
import com.example.security_jwt.service.JwtService;
import com.example.security_jwt.service.MemberDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final MemberDetailsService memberDetailsService;

    private final TokenRepository tokenRepository;

    public JwtAuthenticationFilter(JwtService jwtService, MemberDetailsService memberDetailsService, TokenRepository tokenRepository) {
        this.jwtService = jwtService;
        this.memberDetailsService = memberDetailsService;
        this.tokenRepository = tokenRepository;
    }


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {


        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;
        final String username;

        if (authHeader == null || !authHeader.startsWith("Bearer")) {
            filterChain.doFilter(request, response);
            return;
        }


        jwtToken = authHeader.substring(7);
        username = jwtService.extractUserName(jwtToken);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = memberDetailsService.loadUserByUsername(username);


            if (jwtService.isValid(jwtToken, userDetails)) {

                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                new WebAuthenticationDetailsSource().buildDetails(request);
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));


                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            }


            filterChain.doFilter(request, response);
        }
    }
}
