package com.example.userservice.dto;

import java.time.Instant;

public class UserDetailsResponse {
    private Long id;
    private String email;
    private String provider;
    private String roles;
    private Boolean enabled;
    private Instant createdAt;

    public UserDetailsResponse() {
    }

    public UserDetailsResponse(Long id, String email, String provider, String roles, Boolean enabled, Instant createdAt) {
        this.id = id;
        this.email = email;
        this.provider = provider;
        this.roles = roles;
        this.enabled = enabled;
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
