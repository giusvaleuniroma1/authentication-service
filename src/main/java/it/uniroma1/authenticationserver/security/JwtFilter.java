/**
 * Giuseppe Valente <valentepeppe@gmail.com>
 * A JWT Filter Chain to insert in the authentication spring boot security
 * Is invoked before of the UsernameAuthenticationFilter, then check if a JWT
 * is present in the request.
 * The check is done if and only if a request doesn't request an authentication.
 * 
 * However because Spring Security invokes this filter and is not possible insert
 * a conditional filter, is needed insert manually the URLs to skip
 */
package it.uniroma1.authenticationserver.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import it.uniroma1.authenticationserver.entities.Role;
import it.uniroma1.authenticationserver.entities.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Convert the claims into User object
     * 
     * @param claims The claims of the token
     * @return
     */
    private User createUserbyClaims(Claims claims) {
        if(claims != null) {
            User u = new User();
            u.setUsername(claims.get("username", String.class));
            u.setEnabled(claims.get("enabled", Boolean.class));
            Set<Role> authorities = new HashSet<Role>();
            List<String> stringaAthorities = claims.get("roles", List.class);
            for(String tmp : stringaAthorities) {
                Role r = new Role();
                r.setAuthority(tmp);
                authorities.add(r);
            }
            u.setAuthorities(authorities);
            return u;
        
        }
        return null;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        try {
            if(!isPublicUrl(request)) {
                String token = extractToken(request.getHeader("Authorization"));
                if(token != null) {
                    //1. Check token signature and extract all information
                    Claims claims = jwtUtil.extractAllClaims(token);
                    //2. Check if the token is not expired
                    boolean isTokenExpired = jwtUtil.isTokenExpired(token);
                    //3. Create the user and insert into Security Context
                    if(!isTokenExpired && claims != null) {
                        User u = createUserbyClaims(claims);
                        if(u != null) {
                               UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(u.getUsername(), null, u.getAuthorities());
                               SecurityContextHolder.getContext().setAuthentication(auth); //Authenticate the user
                        }
                    } else {
                        SecurityContextHolder.clearContext();
                        response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired token");    
                    }
    
                } else {
                    SecurityContextHolder.clearContext();
                    response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired token");
                }
            } 
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired token");
            return;
        }

        filterChain.doFilter(request, response); //Go to next filter chain
    }

    private String extractToken(String bearerToken) {
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * Check if the request is allowed without login
     * 
     * @param request The HTTP Request
     * @return
     */
    private boolean isPublicUrl(HttpServletRequest request) {
        
        ArrayList<String> skippableUrls = new ArrayList<String>();
        skippableUrls.add("/");
        skippableUrls.add("/api/public");
        skippableUrls.add("/api/login");

        return skippableUrls.contains(request.getRequestURI());
    }
    
}
