package com.example.security_jwt.service;

import com.example.security_jwt.model.Member;
import com.example.security_jwt.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {

    private final TokenRepository tokenRepository;

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${application.security.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;


    public JwtService(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(Member member) {
        return generateToken(member,accessTokenExpiration); // token geçerlilik süresi 24 saat.
    }


    public String generateRefreshToken(Member member) {
        return generateToken(member,refreshTokenExpiration); // refresh token geçerlilik süresi 7 gün
    }

    private String generateToken(Member member,long expireTime){
        return Jwts.builder()
                .header()
                .add("type", "JWT")
                .and()
                .subject(member.getUsername())
                .claims(mapToClaimJWT(member))
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() +expireTime))
                .signWith(getSigningKey())
                .id(UUID.randomUUID().toString())
                .issuer("security-jwt-application")
                .compact();
    }



    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }



    public boolean isValid(String token, UserDetails userDetails) {
        String username = extractUserName(token);
        boolean isValidToken = tokenRepository.findByAccessToken(token)
                .map(t->!t.isActive())
                .orElse(false);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token) && isValidToken);
    }

    public boolean isValidRefreshToken(String token, Member member) {
        String username = extractUserName(token);
        boolean isValidRefreshToken = tokenRepository.findByRefreshToken(token)
                .map(t->!t.isActive())
                .orElse(false);
        return (username.equals(member.getUsername()) &&!isTokenExpired(token) && isValidRefreshToken);
    }


    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }


    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private static Map<String, Object> mapToClaimJWT(Member member) {
        String name = member.getFirstName().concat(" " + member.getLastName());

        Map<String, Object> mapToClaimJWT = new HashMap<>();
        mapToClaimJWT.put("name", name);
        mapToClaimJWT.put("email", member.getEmail());
        mapToClaimJWT.put("role", member.getRole());
        mapToClaimJWT.put("preference", Map.of("language", "TR", "timezone", "GTM"));
        return mapToClaimJWT;
    }


}
