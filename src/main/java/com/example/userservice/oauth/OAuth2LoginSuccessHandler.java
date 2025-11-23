package com.example.userservice.oauth;

import com.example.userservice.entity.User;
import com.example.userservice.repository.UserRepository;
import com.example.userservice.security.JwtService;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    public OAuth2LoginSuccessHandler(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        String email = (String) oauthUser.getAttributes().get("email");
        if (email == null) {
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

        response.setContentType("application/json");
        response.getWriter().write("{\"token\" :" + token + "}");
        response.getWriter().flush();
    }
}
