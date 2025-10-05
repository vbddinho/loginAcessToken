package com.futebol.vandersondutra.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtil {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.expirationMillis}")
    private long expirationMillis;

    private SecretKey getKey() {
        // Usa bytes diretos (não Base64) para simplicidade; para produção prefira Base64
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String subject, Map<String, Object> claims) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMillis);
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(subject)
            .setIssuedAt(now)
            .setExpiration(expiry)
            .signWith(getKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(getKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }
}



