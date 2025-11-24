package com.ejdev.securitylab.auth.controller;

import com.ejdev.securitylab.auth.dto.AuthRequest;
import com.ejdev.securitylab.auth.dto.AuthResponse;
import com.ejdev.securitylab.auth.dto.RefreshTokenRequest;
import com.ejdev.securitylab.auth.strategy.AuthStrategy;
import com.ejdev.securitylab.auth.strategy.AuthStrategyDispatcher;
import com.ejdev.securitylab.security.jwt.JwtService;
import com.ejdev.securitylab.token.model.RefreshToken;
import com.ejdev.securitylab.token.service.RefreshTokenService;
import com.ejdev.securitylab.user.model.Role;
import com.ejdev.securitylab.user.model.User;
import com.ejdev.securitylab.user.repository.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthStrategyDispatcher dispatcher;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public User register(@RequestBody AuthRequest request) {
        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .roles(Set.of(Role.ROLE_USER))
                .build();
        return userRepository.save(user);
    }

    @PostMapping("/login")
    public AuthResponse login(
            @RequestBody AuthRequest request,
            HttpServletResponse response
    ) {
        AuthResponse authResponse = dispatcher.authenticate(request);

        if (AuthStrategy.JWT.name().equals(authResponse.strategy())
                && authResponse.refreshToken() != null) {

            ResponseCookie cookie = ResponseCookie.from("refreshToken", authResponse.refreshToken())
                    .httpOnly(true)
                    .secure(false) // dev için
                    .path("/api/auth")
                    .maxAge(Duration.ofDays(7))
                    .sameSite("Strict")
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        }

        return authResponse;
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(
            @CookieValue(value = "refreshToken", required = false) String refreshCookie,
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletResponse response
    ) {
        String token = null;

        if (refreshCookie != null && !refreshCookie.isBlank()) {
            token = refreshCookie;
        } else if (body != null && body.refreshToken() != null) {
            token = body.refreshToken();
        }

        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Refresh token is required");
        }

        RefreshToken newRefreshToken = refreshTokenService.verifyAndRotate(token);
        User user = newRefreshToken.getUser();

        Authentication auth = new UsernamePasswordAuthenticationToken(
                user.getUsername(),
                null,
                user.getRoles().stream()
                        .map(r -> new SimpleGrantedAuthority(r.name()))
                        .collect(Collectors.toSet())
        );

        String newAccessToken = jwtService.generateAccessToken(auth);

        ResponseCookie cookie = ResponseCookie.from("refreshToken", newRefreshToken.getToken())
                .httpOnly(true)
                .secure(false)
                .path("/api/auth")
                .maxAge(Duration.ofDays(7))
                .sameSite("Strict")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return AuthResponse.forJwt(newAccessToken, newRefreshToken.getToken());
    }

    @PostMapping("/logout")
    public void logout(
            @CookieValue(value = "refreshToken", required = false) String refreshCookie,
            HttpServletResponse response
    ) {
        if (refreshCookie != null && !refreshCookie.isBlank()) {
            refreshTokenService.revoke(refreshCookie);
        }

        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(false)
                .path("/api/auth")
                .maxAge(0)
                .sameSite("Strict")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());
    }
}