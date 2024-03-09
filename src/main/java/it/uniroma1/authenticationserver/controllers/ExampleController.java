/**
 * @author Giuseppe Valente <valentepeppe@gmail.com>
 */
package it.uniroma1.authenticationserver.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import it.uniroma1.authenticationserver.security.CustomAuth;
import it.uniroma1.authenticationserver.security.JwtUtil;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;


@RestController
public class ExampleController {

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
              //Sign the token with the username enough information to retrieve all data
              String token = jwtUtil.generateToken(authentication.getName());
              if(token != null) {
                return ResponseEntity.ok(token);
              } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Problem during the generation of JWT token");
              }
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Username/Password not valid");
            }
        
        } catch(Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
    


    @GetMapping("/api/public")
    public String publicEndpoint() {
        return "Public endpoint";
    }

    @GetMapping("/api/private")
    @PreAuthorize("hasRole('ADMIN')")
    public String privateEndpoint() {
        return "Private endpoint";
    }
}
