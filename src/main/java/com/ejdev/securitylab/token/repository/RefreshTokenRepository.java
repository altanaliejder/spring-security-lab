package com.ejdev.securitylab.token.repository;

import com.ejdev.securitylab.token.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked=true, rt.used=true WHERE rt.user.id = :userId AND rt.revoked = false")
    void revokeAllByUser(Long userId);
}