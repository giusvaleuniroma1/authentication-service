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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Date;

import java.util.HashMap;
import java.util.List;
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

    /**
     * In the JWT will be insert:
     * 1) The username
     * 2) The list of authorities
     * 3) The information about the enable
     * 
     * The JWT will be sign with these information
     * 
     * @param user The user to sign in JWT
     * @return The Signed JWT
     * @throws Exception
     */
    public String generateToken(UserDetails user) throws Exception {

        Map<String, Object> claims = new HashMap<>();
        if(user == null || user.getUsername() == null || user.getUsername().trim().equals("")) {
            throw new Exception("Invalid user");
        }

        claims.put("username", user.getUsername());
        claims.put("enabled", user.isEnabled());
        List<String> roles = new ArrayList<String>();
        for(GrantedAuthority ga : user.getAuthorities()) {
            if(ga != null) {
                roles.add(ga.getAuthority());
            }
        }

        claims.put("roles", roles);
        return createToken(claims, "user");
    }

    /**
     * Sign the JWT token
     * 
     * @param claims The claims
     * @param subject The subject
     * @return The signed JWT
     * @throws UnsupportedEncodingException
     */
    public String createToken(Map<String, Object> claims, String subject) throws UnsupportedEncodingException {

        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA256");

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 60 minutes validation
                .signWith(key).compact();
    }

    public Boolean validateToken(String token, UserDetails user) throws UnsupportedEncodingException {
        final String userName = extractUsername(token);
        return (userName.equals(user.getUsername()) && !isTokenExpired(token));
    }
}
