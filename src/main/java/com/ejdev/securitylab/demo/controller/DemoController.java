package com.ejdev.securitylab.demo.controller;

import com.ejdev.securitylab.auth.annotation.EmailVerified;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

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

    @PostMapping("/resend-verification-email")
    @PreAuthorize("@authz.requireUnverifiedEmail(authentication)")
    public String resendVerificationEmail(Authentication authentication) {
        return "Verification email sent to " + authentication.getName();
    }

    @GetMapping("/verify-email")
    @PreAuthorize("isAuthenticated()")
    public String verifyEmail(@RequestParam String token) {
        return "Verification email sent to " + token;
    }

    @GetMapping("/profile")
    @EmailVerified
    public String profile(Authentication authentication) {
        return "Profile of " + authentication.getName();
    }
}
