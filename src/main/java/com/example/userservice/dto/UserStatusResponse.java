package com.example.userservice.dto;

public class UserStatusResponse {
    private Long userId;
    private boolean enabled;

    public UserStatusResponse() {
    }

    public UserStatusResponse(Long userId, boolean enabled) {
        this.userId = userId;
        this.enabled = enabled;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
