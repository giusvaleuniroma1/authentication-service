package it.uniroma1.authenticationserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import io.jsonwebtoken.Claims;

import it.uniroma1.authenticationserver.entities.Role;
import it.uniroma1.authenticationserver.entities.User;
import it.uniroma1.authenticationserver.repositories.RoleRepository;
import it.uniroma1.authenticationserver.repositories.UserRepository;
import it.uniroma1.authenticationserver.security.JwtUtil;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class LoginControllerTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    private User superadmin; // A user with superadmin role
    private User systemAdminUser; // A user with the role systemadmin
    private User disabledUser; // A disabled user
    

    private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    /**
     * Runned before of all tests
     */
    @SuppressWarnings("null")
    @BeforeEach
    public void setUp() {

        //Clear all database
        userRepository.deleteAll();
        roleRepository.deleteAll();

        Role roleSuperadmin = new Role();
        roleSuperadmin.setAuthority("ROLE_SUPERADMIN");
        roleSuperadmin = roleRepository.save(roleSuperadmin);

        Role roleSystemAdministrator = new Role();
        roleSystemAdministrator.setAuthority("ROLE_SYSTEM_ADMINISTRATOR");
        roleSystemAdministrator = roleRepository.save(roleSystemAdministrator);
        
        // Create users with right roles
        superadmin = new User();
        superadmin.setEmail("superadmin");
        superadmin.setUsername("superadmin");
        superadmin.setPassword(bCryptPasswordEncoder.encode("HelloWolrd!123"));
        superadmin.setName("superadmin");
        superadmin.setSurname("superadmin");
        superadmin.setEnabled(true);

        Set<Role> superadminRoles = new HashSet<Role>();
        superadminRoles.add(roleSuperadmin);
        superadminRoles.add(roleSystemAdministrator);
        superadmin.setAuthorities(superadminRoles);
        superadmin = userRepository.save(superadmin);

        Set<Role> systemAdminRoles = new HashSet<Role>();
        systemAdminRoles.add(roleSystemAdministrator);

        disabledUser = new User();
        disabledUser.setEmail("disabledUser");
        disabledUser.setUsername("disabledUser");
        disabledUser.setPassword(bCryptPasswordEncoder.encode("HelloWolrd!123"));
        disabledUser.setName("disabledUser");
        disabledUser.setSurname("disabledUser");
        disabledUser.setEnabled(false);
        disabledUser.setAuthorities(superadminRoles);
        disabledUser = userRepository.save(disabledUser);

        systemAdminUser = new User();
        systemAdminUser.setEmail("systemAdminUser");
        systemAdminUser.setUsername("systemAdminUser");
        systemAdminUser.setPassword(bCryptPasswordEncoder.encode("HelloWolrd!123"));
        systemAdminUser.setName("systemAdminUser");
        systemAdminUser.setSurname("systemAdminUser");
        systemAdminUser.setEnabled(true);
        systemAdminUser.setAuthorities(systemAdminRoles); 
        systemAdminUser = userRepository.save(systemAdminUser);

    }

    @Test
    public void testLoginSuccesfull() {

        // Create a multimap to hold the named parameters
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();
        parameters.add("username", superadmin.getUsername());
        parameters.add("password", "HelloWolrd!123");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(parameters, headers);

        // Make the POST request
        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/api/login",
                requestEntity,
                String.class);
        assertNotNull(response);
        assertEquals(HttpStatusCode.valueOf(200), response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    public void testJwtTokenVerification() {
          // Create a multimap to hold the named parameters
          MultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();
          parameters.add("username", superadmin.getUsername());
          parameters.add("password", "HelloWolrd!123");
  
          HttpHeaders headers = new HttpHeaders();
          headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
  
          HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(parameters, headers);
  
          // Make the POST request
          ResponseEntity<String> response = restTemplate.postForEntity(
                  "http://localhost:" + port + "/api/login",
                  requestEntity,
                  String.class);
          assertNotNull(response);
          assertEquals(HttpStatusCode.valueOf(200), response.getStatusCode());
          assertNotNull(response.getBody());
          Claims claims = null;
          try {
              claims = jwtUtil.extractAllClaims(response.getBody());
              assertNotNull(claims);
              assertEquals(claims.get("username"), superadmin.getUsername());
              assertEquals(claims.get("enabled"), true);
              @SuppressWarnings("unchecked")
              List<String> rolesString = (List<String>) claims.get("roles");
              assertTrue(rolesString.contains("ROLE_SYSTEM_ADMINISTRATOR"));
              assertTrue(rolesString.contains("ROLE_SUPERADMIN"));
        } catch (UnsupportedEncodingException e) {
            assertFalse(true);
        }
    }

    @Test
    public void testLoginFailureForDisabledUser() {
         // Create a multimap to hold the named parameters
         MultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();
         parameters.add("username", disabledUser.getUsername());
         parameters.add("password", "HelloWolrd!123");
 
         HttpHeaders headers = new HttpHeaders();
         headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
 
         HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(parameters, headers);
 
         // Make the POST request
         ResponseEntity<String> response = restTemplate.postForEntity(
                 "http://localhost:" + port + "/api/login",
                 requestEntity,
                 String.class);
         assertNotNull(response);
         assertEquals(HttpStatusCode.valueOf(403), response.getStatusCode());
         assertEquals("Username/Password not valid", response.getBody());
    }

    @Test
    public void testAccessToSuperUserResource() {
        // Create a multimap to hold the named parameters
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();
        parameters.add("username", superadmin.getUsername());
        parameters.add("password", "HelloWolrd!123");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(parameters, headers);

        // Make the POST request
        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/api/login",
                requestEntity,
                String.class);

        String token = response.getBody();
        assertNotNull(token);

        headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBearerAuth(token);

        requestEntity = new HttpEntity<>(headers);

        ResponseEntity<String> respEntity = restTemplate.exchange("http://localhost:" + port + "/api/private/superadmin_resource", HttpMethod.GET, requestEntity, String.class);

        assertEquals(HttpStatusCode.valueOf(200), respEntity.getStatusCode());
    }

    @Test
    public void testAccessToSystemAdministratorResource() {
        // Create a multimap to hold the named parameters
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();
        parameters.add("username", superadmin.getUsername());
        parameters.add("password", "HelloWolrd!123");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(parameters, headers);

        // Make the POST request
        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/api/login",
                requestEntity,
                String.class);

        String token = response.getBody();
        assertNotNull(token);

        headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBearerAuth(token);

        requestEntity = new HttpEntity<>(headers);

        ResponseEntity<String> respEntity = restTemplate.exchange("http://localhost:" + port + "/api/private/system_administrator_resource", HttpMethod.GET, requestEntity, String.class);

        assertEquals(HttpStatusCode.valueOf(200), respEntity.getStatusCode());
    }

    @Test
    public void denyAccessToSuperadminResource() {
         // Create a multimap to hold the named parameters
         MultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();
         parameters.add("username", systemAdminUser.getUsername()); //Doesn't have right role but is able to login
         parameters.add("password", "HelloWolrd!123");
 
         HttpHeaders headers = new HttpHeaders();
         headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
 
         HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(parameters, headers);
 
         // Make the POST request
         ResponseEntity<String> response = restTemplate.postForEntity(
                 "http://localhost:" + port + "/api/login",
                 requestEntity,
                 String.class);
 
         String token = response.getBody();
         assertNotNull(token);
 
         headers = new HttpHeaders();
         headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
         headers.setBearerAuth(token);
 
         requestEntity = new HttpEntity<>(headers);
 
         ResponseEntity<String> respEntity = restTemplate.exchange("http://localhost:" + port + "/api/private/superadmin_resource", HttpMethod.GET, requestEntity, String.class);
 
         assertEquals(HttpStatusCode.valueOf(401), respEntity.getStatusCode());
    }

}
