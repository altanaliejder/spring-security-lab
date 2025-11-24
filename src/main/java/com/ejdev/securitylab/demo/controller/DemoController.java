package com.ejdev.securitylab.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DemoController {

    @GetMapping("/public/hello")
    public String publicHello() {
        return "Hello from PUBLIC endpoint";
    }

    @GetMapping("/user/me")
    public String me(Authentication authentication) {
        return "Hello " + authentication.getName();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/secret")
    public String adminSecret(Authentication authentication) {
        return "Admin secret for " + authentication.getName();
    }
}
