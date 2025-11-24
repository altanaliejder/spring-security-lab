package com.ejdev.securitylab.token.service;

import com.ejdev.securitylab.token.model.RefreshToken;
import com.ejdev.securitylab.token.repository.RefreshTokenRepository;
import com.ejdev.securitylab.user.entity.User;
import com.ejdev.securitylab.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @Value("${security.jwt.refresh-token-expiration-ms}")
    private long REFRESH_TOKEN_TTL;

    @Transactional
    public RefreshToken createRefreshToken(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

         refreshTokenRepository.revokeAllByUser(user.getId());

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(generateRandomToken())
                .expiryDate(Instant.now().plusMillis(REFRESH_TOKEN_TTL))
                .revoked(false)
                .used(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional(readOnly = true)
    public RefreshToken validateAndGet(String tokenValue) {

        RefreshToken token = refreshTokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new IllegalArgumentException("Geçersiz refresh token."));

        if (token.isRevoked()) {
            throw new IllegalArgumentException("Refresh token revocation nedeniyle iptal edilmiştir.");
        }

        if (token.isUsed()) {
            throw new IllegalArgumentException("Refresh token daha önce kullanılmıştır.");
        }

        if (token.getExpiryDate().isBefore(Instant.now())) {
            throw new IllegalArgumentException("Refresh token süresi dolmuştur.");
        }

        return token;
    }

    public String generateRandomToken() {
        // TODO: more secure token generation
        return UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID();
    }

    public String rotate(RefreshToken oldToken) {

        oldToken.setUsed(true);
        oldToken.setRevoked(true);
        refreshTokenRepository.save(oldToken);

        String newTokenValue = UUID.randomUUID().toString();

        RefreshToken newToken = RefreshToken.builder()
                .token(newTokenValue)
                .user(oldToken.getUser())
                .expiryDate(Instant.now().plusMillis(REFRESH_TOKEN_TTL))
                .revoked(false)
                .used(false)
                .build();

        refreshTokenRepository.save(newToken);

        return newTokenValue;
    }


    @Transactional
    public void revoke(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(rt -> {
            rt.setRevoked(true);
            rt.setUsed(true);
            refreshTokenRepository.save(rt);
        });
    }

    @Transactional
    public void revokeAllTokensOfUser(Long userId) {
        refreshTokenRepository.revokeAllByUser(userId);
    }
}