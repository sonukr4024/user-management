package org.usermanagement.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Component

public class JwtUtil {
    private final String key = "dGhpcy1pcy1teS1zdXBlci1zZWNyZXQta2V5LXdpdGgtc29tZS1leHRyYS1zZWN1cml0eQ==";

    public String generateToken(String mobile, String role) {
        return Jwts.builder()
                .setSubject(mobile)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(key)), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractMobile(String token) {
        return Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String mobile = extractMobile(token);
        return (mobile.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        Date expiration = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody().getExpiration();
        return expiration.before(new Date());
    }
}
