/**
 * @author Giuseppe Valente <valentepeppe@gmail.com>
 */
package it.uniroma1.authenticationserver.controllers;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import it.uniroma1.authenticationserver.entities.Role;
import it.uniroma1.authenticationserver.entities.User;
import it.uniroma1.authenticationserver.security.CustomAuth;
import it.uniroma1.authenticationserver.security.JwtUtil;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;


@RestController
public class LoginController {

    @Autowired
    private CustomAuth customAuth;

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Check if the user is authenticated or not
     * 
     * @param username The username
     * @param password The password
     * @return the JWT Token if the user is authenticated
     */
    @PostMapping("/api/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {

        try {
            
            Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);
            authentication = customAuth.authenticate(authentication);
            if(authentication != null) {
              User u = new User();
              u.setUsername(authentication.getName());
              Set<Role> roles = new HashSet<Role>();
              for(GrantedAuthority ga : authentication.getAuthorities()) {
                roles.add((Role) ga);
              }
              u.setEnabled(true); //The authentication is done, the user is enabled to login
              u.setAuthorities(roles);
              String token = jwtUtil.generateToken(u);
              if(token != null) {
                return ResponseEntity.status(HttpStatus.OK).body(token);
              } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Problem during the generation of JWT token");
              }
            } else {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Username/Password not valid");
            }
        
        } catch(Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
    
    @GetMapping("/api/public")
    public String publicEndpoint() {
        return "Public endpoint test purpose";
    }

    @GetMapping("/api/private/superadmin_resource")
    @PreAuthorize("hasRole('SUPERADMIN')")
    public String privateSuperadminEndpoint() {
        return "Superadmin resource";
    }

    @GetMapping("/api/private/system_administrator_resource")
    @PreAuthorize("hasRole('SYSTEM_ADMINISTRATOR')")
    public String privateSystemAdministratorEndpoint() {
        return "System Administrator resource";
    }
}
