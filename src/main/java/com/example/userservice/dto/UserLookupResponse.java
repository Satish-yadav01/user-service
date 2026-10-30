package com.example.userservice.dto;

import java.time.Instant;

public class UserLookupResponse {
    private Long userId;
    private String email;
    private String provider;
    private String roles;
    private Boolean enabled;
    private Instant createdAt;

    public UserLookupResponse(Long userId, String email, String provider, String roles,
                              Boolean enabled, Instant createdAt) {
        this.userId = userId;
        this.email = email;
        this.provider = provider;
        this.roles = roles;
        this.enabled = enabled;
        this.createdAt = createdAt;
    }

    public Long getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    public String getProvider() {
        return provider;
    }

    public String getRoles() {
        return roles;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
