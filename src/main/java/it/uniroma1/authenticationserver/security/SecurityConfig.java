/**
 * Giuseppe Valente <valentepeppe@gmail.com>
 */

package it.uniroma1.authenticationserver.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	private CustomAuth customAuth;

	@Autowired
	private JwtFilter jwtFilter;


    @Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
            .csrf((csrf) -> csrf.disable())
			.authorizeHttpRequests((requests) -> requests
				.requestMatchers("/", "/api/public", "/api/login").permitAll()
				
				.anyRequest().authenticated()
			)
            .httpBasic(Customizer.withDefaults())
			.addFilterBefore(new PublicEndpointFilter(), UsernamePasswordAuthenticationFilter.class) //Allowing public pages (filter)
			.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class) //Allowing to process JWT token
            .sessionManagement( (session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
			
		
		return http.build();
	}

	@Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = 
            http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(customAuth);
        return authenticationManagerBuilder.build();
    } 

	/**
	 * Filter that allows to process the public pages without passing for the Authentication
	 */
	private static class PublicEndpointFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException, java.io.IOException {
            if (isPublicEndpoint(request)) {
                filterChain.doFilter(request, response);
            } else {
                super.doFilter(request, response, filterChain);
            }
        }
		private boolean isPublicEndpoint(HttpServletRequest request) {
			List<String> publicEndpoints = new ArrayList<String>();
			publicEndpoints.add("/api/public");
			publicEndpoints.add("/api/login");
			return publicEndpoints.contains(request.getRequestURI());
		}
	}
}
