package com.example.userservice.controller;

import com.example.userservice.dto.UserDetailsResponse;
import com.example.userservice.dto.UserLookupRequest;
import com.example.userservice.dto.UserLookupResponse;
import com.example.userservice.dto.UserStatusResponse;
import com.example.userservice.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Slf4j
@RestController
@RequestMapping("/api/v1/internal/users")
public class UserStatusController {

    private final UserRepository userRepository;
    private final byte[] serviceApiKey;

    public UserStatusController(
            UserRepository userRepository,
            @Value("${user-service.api-key:}") String serviceApiKey) {
        this.userRepository = userRepository;
        this.serviceApiKey = serviceApiKey.getBytes(StandardCharsets.UTF_8);
    }

    @GetMapping("/by-email")
    public ResponseEntity<UserDetailsResponse> getUserByEmail(
            @RequestParam("email") String email,
            @RequestHeader(value = "X-Internal-Api-Key", required = false) String apiKey) {
        if (!isAuthorized(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (email.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        return userRepository.findByEmail(email.trim())
                .map(user -> ResponseEntity.ok(new UserDetailsResponse(
                        user.getId(),
                        user.getEmail(),
                        user.getProvider(),
                        user.getRoles(),
                        user.getEnabled(),
                        user.getCreatedAt()
                )))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/by-email")
    public ResponseEntity<UserLookupResponse> getUserByEmail(
            @RequestBody UserLookupRequest request) {
//        if (!isAuthorized(apiKey)) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
//        }
//        if (request == null || request.getEmail() == null || request.getEmail().isBlank()) {
//            return ResponseEntity.badRequest().build();
//        }

        return userRepository.findByEmail(request.getEmail().trim())
                .map(user -> ResponseEntity.ok(new UserLookupResponse(
                        user.getId(),
                        user.getEmail(),
                        user.getProvider(),
                        user.getRoles(),
                        user.getEnabled(),
                        user.getCreatedAt()
                )))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private boolean isAuthorized(String apiKey) {
        return serviceApiKey.length > 0 && apiKey != null
                && MessageDigest.isEqual(serviceApiKey, apiKey.getBytes(StandardCharsets.UTF_8));
    }

    @GetMapping("/{userId}/status")
    public ResponseEntity<UserStatusResponse> getUserStatus(
            @PathVariable Long userId,
            @RequestHeader(value = "X-Internal-Api-Key", required = false) String apiKey) {
        if (!isAuthorized(apiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        ResponseEntity<UserStatusResponse> userStatusResponseResponseEntity = userRepository.findEnabledById(userId)
                .map(enabled -> {
                    log.info("Getting user status for userId: {}, enabled: {}", userId, enabled);
                    return ResponseEntity.ok(new UserStatusResponse(userId, Boolean.TRUE.equals(enabled)));
                })
                .orElseGet(() -> {
                    log.error("User not found with ID: {}", userId);
                    return ResponseEntity.notFound().build();
                });

        log.info("User status request for userId: {} returned status: {}", userId, userStatusResponseResponseEntity.getStatusCode());
        return userStatusResponseResponseEntity;
    }


}
