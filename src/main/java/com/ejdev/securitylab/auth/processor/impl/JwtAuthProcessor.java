package com.ejdev.securitylab.auth.processor.impl;

import com.ejdev.securitylab.auth.dto.AuthRequest;
import com.ejdev.securitylab.auth.dto.AuthResponse;
import com.ejdev.securitylab.auth.processor.AuthProcessor;
import com.ejdev.securitylab.auth.strategy.AuthStrategy;
import com.ejdev.securitylab.security.jwt.JwtService;
import com.ejdev.securitylab.token.model.RefreshToken;
import com.ejdev.securitylab.token.service.RefreshTokenService;
import com.ejdev.securitylab.user.service.UserDetailService;
import com.ejdev.securitylab.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtAuthProcessor implements AuthProcessor {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserDetailService userDetailService;

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

    @Override
    public AuthResponse refresh(String refreshTokenValue) {
        RefreshToken refreshToken = refreshTokenService.validateAndGet(refreshTokenValue);
        String username = refreshToken.getUser().getUsername();

        UserDetails userDetails = userDetailService.loadUserByUsername(username);

        String newAccessToken = jwtService.generateAccessToken((Authentication) userDetails);

        String newRefreshToken = refreshTokenService.rotate(refreshToken);

        return new AuthResponse(
                AuthStrategy.JWT.name(),
                newAccessToken,
                newRefreshToken,
                null
                );
    }
}
