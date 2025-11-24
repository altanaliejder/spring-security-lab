package com.ejdev.securitylab.auth.service.impl;

import com.ejdev.securitylab.auth.dto.AuthRequest;
import com.ejdev.securitylab.auth.dto.AuthResponse;
import com.ejdev.securitylab.auth.service.AuthProcessor;
import com.ejdev.securitylab.security.jwt.JwtService;
import com.ejdev.securitylab.token.model.RefreshToken;
import com.ejdev.securitylab.token.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtAuthProcessor implements AuthProcessor {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Override
    public AuthResponse authenticate(AuthRequest request) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                );

        Authentication auth = authenticationManager.authenticate(authToken);

        String accessToken = jwtService.generateAccessToken(auth);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(auth.getName());
        return AuthResponse.forJwt(accessToken, refreshToken.getToken());
    }
}
