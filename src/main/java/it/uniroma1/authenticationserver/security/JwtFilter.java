/**
 * Giuseppe Valente <valentepeppe@gmail.com>
 */
package it.uniroma1.authenticationserver.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import it.uniroma1.authenticationserver.entities.User;
import it.uniroma1.authenticationserver.repositories.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter{

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        try {
            String token = extractToken(request.getHeader("Authorization"));
            if(token != null) {
                //1. Check token signature and extract all information
                Claims claims = jwtUtil.extractAllClaims(token);
                //2. Check if the token is not expired
                boolean isTokenExpired = jwtUtil.isTokenExpired(token);
                //3. Create the user and insert into Security Context
                if(!isTokenExpired && claims != null) {
                    String username = claims.get("username", String.class);
                    if(username != null) {
                        User u = userRepository.findByUsername(username);
                        if(u != null) {
                           UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, u, u.getAuthorities());
                           SecurityContextHolder.getContext().setAuthentication(auth); //Authenticate the user
                        }
                    }
                } else {
                    SecurityContextHolder.clearContext();
                    response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired token");    
                }

            } else {
                SecurityContextHolder.clearContext();
                response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired token");
            }
            
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired token");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String extractToken(String bearerToken) {
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
    
}
