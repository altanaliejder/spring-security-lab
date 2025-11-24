package com.ejdev.securitylab.auth.controller;

import com.ejdev.securitylab.auth.dto.AuthRequest;
import com.ejdev.securitylab.auth.dto.AuthResponse;
import com.ejdev.securitylab.auth.dto.RefreshTokenRequest;
import com.ejdev.securitylab.auth.dto.RegisterRequest;
import com.ejdev.securitylab.auth.service.AuthenticationService;
import com.ejdev.securitylab.user.model.UserDTO;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authService;

    @PostMapping("/register")
    public ResponseEntity<UserDTO> register(@Valid @RequestBody RegisterRequest request) {
        var user = authService.register(request);
        var dto = UserDTO.from(user); // küçük bir DTO class, id/username/email dön
        return ResponseEntity.ok(dto);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody AuthRequest request,
            HttpServletResponse response
    ) {
        AuthResponse authResponse = authService.login(request);

        return getAuthResponseResponseEntity(response, authResponse);
    }

    private ResponseEntity<AuthResponse> getAuthResponseResponseEntity(HttpServletResponse response, AuthResponse authResponse) {
        if (authResponse.refreshToken() != null) {
            ResponseCookie cookie = ResponseCookie.from("refreshToken", authResponse.refreshToken())
                    .httpOnly(true)
                    .secure(false) // prod'da true
                    .path("/api/auth")
                    .maxAge(Duration.ofDays(7))
                    .sameSite("Strict")
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        }

        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @CookieValue(value = "refreshToken", required = false) String refreshCookie,
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletResponse response
    ) {
        String token = refreshCookie;
        if ((token == null || token.isBlank()) && body != null) {
            token = body.refreshToken();
        }
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Refresh token gerekli.");
        }

        AuthResponse authResponse = authService.refresh(token);

        return getAuthResponseResponseEntity(response, authResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @CookieValue(value = "refreshToken", required = false) String refreshCookie,
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletResponse response
    ) {
        String token = refreshCookie;
        if ((token == null || token.isBlank()) && body != null) {
            token = body.refreshToken();
        }

        if (token != null && !token.isBlank()) {
            authService.logout(token);
        }
        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(false)
                .path("/api/auth")
                .maxAge(0)
                .sameSite("Strict")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());

        return ResponseEntity.noContent().build();
    }
}