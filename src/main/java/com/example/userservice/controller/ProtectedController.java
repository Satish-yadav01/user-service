package com.example.userservice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/protected")
public class ProtectedController {

    @GetMapping()
    public String secured() {
        return "This is protected and requires a valid JWT.";
    }
}
