package com.ejdev.securitylab.token.service;

import com.ejdev.securitylab.token.model.RefreshToken;
import com.ejdev.securitylab.token.repository.RefreshTokenRepository;
import com.ejdev.securitylab.user.model.User;
import com.ejdev.securitylab.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @Value("${security.jwt.refresh-token-expiration-ms}")
    private long refreshTokenExpirationMs;

    @Transactional
    public RefreshToken createRefreshToken(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

         refreshTokenRepository.revokeAllByUser(user.getId());

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(generateRandomToken())
                .expiryDate(Instant.now().plusMillis(refreshTokenExpirationMs))
                .revoked(false)
                .used(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    public String generateRandomToken() {
        // TODO: more secure token generation
        return UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID();
    }

    @Transactional
    public RefreshToken verifyAndRotate(String token) {
        RefreshToken existing = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));

        if (existing.isRevoked()) {
            throw new IllegalStateException("Refresh token revoked");
        }
        if (existing.isUsed()) {
            throw new IllegalStateException("Refresh token already used");
        }
        if (existing.getExpiryDate().isBefore(Instant.now())) {
            throw new IllegalStateException("Refresh token expired");
        }

        existing.setUsed(true);
        existing.setRevoked(true);
        refreshTokenRepository.save(existing);

        User user = existing.getUser();
        RefreshToken newToken = RefreshToken.builder()
                .user(user)
                .token(generateRandomToken())
                .expiryDate(Instant.now().plusMillis(refreshTokenExpirationMs))
                .revoked(false)
                .used(false)
                .build();

        return refreshTokenRepository.save(newToken);
    }

    @Transactional
    public void revoke(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(rt -> {
            rt.setRevoked(true);
            rt.setUsed(true);
            refreshTokenRepository.save(rt);
        });
    }
}