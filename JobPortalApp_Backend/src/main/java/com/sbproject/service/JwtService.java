package com.sbproject.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    // Keep your original secret key logic
    private static final String SECRET_KEY = Base64.getEncoder().encodeToString("my_secret_key1234567890".getBytes());

    // ---------------- Generate Token ----------------
    public String generateToken(String email, String role) {
        return Jwts.builder()
                .setSubject(email) // keep email as subject
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // ---------------- Extract Claims ----------------
    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = parseClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // ---------------- Token Validation ----------------
    public boolean validateToken(String token, UserDetails userDetails) {
        final String email = extractEmail(token);
        final String role = extractRole(token);

        // Compare email + role from token with UserDetails
        return email.equals(userDetails.getUsername()) // username = email in your system
                && roleMatchesUser(userDetails, role)
                && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    private boolean roleMatchesUser(UserDetails userDetails, String tokenRole) {
        // assuming one role per user
        return userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals(tokenRole));
    }

    // ---------------- Signing Key ----------------
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }
}
