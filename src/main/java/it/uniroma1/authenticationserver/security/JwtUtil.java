/**
 * @author Giuseppe Valente <valentepeppe@gmail.com>
 * 
 * JWT Utils implementation
 * 
 * 
 */
package it.uniroma1.authenticationserver.security;

import io.jsonwebtoken.Claims;

import io.jsonwebtoken.Jwts;


import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;

import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;

import java.util.Date;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {

    @Value("${jwt.symmetric.key}")
    private String secretKey;

    public String extractUsername(String token) throws UnsupportedEncodingException {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) throws UnsupportedEncodingException {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) throws UnsupportedEncodingException {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) throws UnsupportedEncodingException {
        SecretKeySpec secret_key = new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA256");
        return Jwts.parser().verifyWith(secret_key).build().parseSignedClaims(token).getPayload();
    }

    public Boolean isTokenExpired(String token) throws UnsupportedEncodingException {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(String username) throws Exception {

        Map<String, Object> claims = new HashMap<>();
        if (username == null) {
            throw new Exception("Invalid user");
        }
        
        claims.put("username", username);
        
        return createToken(claims, "user");
    }

    public String createToken(Map<String, Object> claims, String subject) throws UnsupportedEncodingException {

        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA256");

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(key)
                .compact();
    }

    public Boolean validateToken(String token, String username) throws UnsupportedEncodingException {
        final String userName = extractUsername(token);
        return (userName.equals(username) && !isTokenExpired(token));
    }
}
