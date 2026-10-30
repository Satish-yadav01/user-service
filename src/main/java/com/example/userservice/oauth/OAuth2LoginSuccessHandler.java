package com.example.userservice.oauth;

import com.example.userservice.entity.User;
import com.example.userservice.repository.UserRepository;
import com.example.userservice.security.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Slf4j
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final String frontendCallbackUrl;

    public OAuth2LoginSuccessHandler(JwtService jwtService, UserRepository userRepository,
                                     @Value("${app.frontend.oauth-callback-url:http://localhost:5173/auth/callback}") String frontendCallbackUrl) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.frontendCallbackUrl = frontendCallbackUrl;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        log.info("OAuth2 login successful for user: {}", authentication.getName());
        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        String email = (String) oauthUser.getAttributes().get("email");
        if (email == null) {
            log.info("OAuth2 login successful for user: {} but email is null", authentication.getName());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Email not available from provider");
            return;
        }

        Optional<User> uOpt = userRepository.findByEmail(email);
        User user;
        if (uOpt.isPresent()) {
            user = uOpt.get();
        } else {
            user = new User();
            user.setEmail(email);
            user.setProvider("GOOGLE");
            user.setRoles("ROLE_USER");
            userRepository.save(user);
        }

        String token = jwtService.generateToken(user.getEmail());
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.sendRedirect(frontendCallbackUrl + "#token="
                + URLEncoder.encode(token, StandardCharsets.UTF_8.name())
                + "&tokenType=Bearer");

        log.info("Redirecting to frontend callback URL with token for user: {}", email);
    }
}
