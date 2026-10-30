package com.example.userservice.config;

import com.example.userservice.constant.AuthConstants;
import com.example.userservice.oauth.OAuth2LoginSuccessHandler;
import com.example.userservice.repository.UserRepository;
import com.example.userservice.security.JwtAuthenticationFilter;
import com.example.userservice.security.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.Customizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static com.example.userservice.constant.AuthConstants.AUTH_CONTEXT_PATH;

@Configuration
@Slf4j
public class SecurityConfig {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final String frontendCallbackUrl;

    public SecurityConfig(JwtService jwtService, UserRepository userRepository,
                          @Value("${app.frontend.oauth-callback-url:http://localhost:5173/auth/callback}") String frontendCallbackUrl) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.frontendCallbackUrl = frontendCallbackUrl;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("Configuring security filter chain with http : {}", http);
        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtService, userRepository);

        // Log after JWT filter runs so we can see the final authentication result for the request
        OncePerRequestFilter requestLoggingFilter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
                // continue the chain first so JwtAuthenticationFilter can set authentication
                filterChain.doFilter(request, response);

                org.springframework.security.core.Authentication auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();

                boolean authenticated = auth != null && auth.isAuthenticated();
                String principal = (auth != null && auth.getName() != null) ? auth.getName() : "none";

                log.info("Request [{} {}] -> authenticated: {} (principal: {})", request.getMethod(), request.getRequestURI(), authenticated, principal);
            }
        };

        http
            .cors(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.requestMatchers(
                            new AntPathRequestMatcher(AUTH_CONTEXT_PATH + "/**"),
                            new AntPathRequestMatcher(AuthConstants.AUTH_DIRECT_PATH + "/**"),
                            new AntPathRequestMatcher("/api/v1/internal/users/**"),
                            new AntPathRequestMatcher("/swagger-ui/**"),
                            new AntPathRequestMatcher("/oauth2/**"),
                            new AntPathRequestMatcher("/actuator/**"))
                    .permitAll()
                    .anyRequest()
                    .authenticated())
            .oauth2Login(oauth2 -> oauth2
                    .redirectionEndpoint(redirection -> redirection.baseUri("/login/oauth2/code/*"))
                    .successHandler(new OAuth2LoginSuccessHandler(jwtService, userRepository, frontendCallbackUrl))
            ).addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(requestLoggingFilter, JwtAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.allowed-origins:http://localhost:3000,http://localhost:5173,http://localhost:4200,https://mail-desk-three.vercel.app}")
            String allowedOrigins) {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isEmpty())
                .toList());
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
