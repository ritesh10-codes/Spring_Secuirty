package com.example.Spring.Security.Demo.JWT;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JWTUtil {
    // ✅ Generate secure random secret key
    private final SecretKey secret = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // ✅ Expiration time in milliseconds (e.g., 1 hour)
    private final long expiration = 60 * 60 * 1000;


    public String generateToken(String username){
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+expiration))
                .signWith(SignatureAlgorithm.HS256,secret)
                .compact();
    }

    public String extractUsername(String token){
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validatetoken(String token){
        try{
            Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
            return true;
        }catch (Exception e){
            return false;
        }
    }
}
