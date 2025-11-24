package com.ejdev.securitylab.auth.service;

import com.ejdev.securitylab.auth.dto.AuthRequest;
import com.ejdev.securitylab.auth.dto.AuthResponse;
import com.ejdev.securitylab.auth.dto.RegisterRequest;
import com.ejdev.securitylab.auth.strategy.AuthStrategyDispatcher;
import com.ejdev.securitylab.token.service.RefreshTokenService;
import com.ejdev.securitylab.user.entity.User;
import com.ejdev.securitylab.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AuthStrategyDispatcher authStrategyDispatcher;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService; // register / user ops

    public User register(RegisterRequest request) {
        return userService.register(request);
    }

    public AuthResponse login(AuthRequest request) {
        return authStrategyDispatcher.authenticate(request);
    }

    public AuthResponse refresh( String refreshToken) {
        return authStrategyDispatcher.refresh(refreshToken);
    }

    public void logout(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("Refresh token gerekli.");
        }
        refreshTokenService.revoke(refreshToken);
    }
}