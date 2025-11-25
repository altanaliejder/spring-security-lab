package com.ejdev.securitylab.security.jwt;


import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    // Access token süresi (örnek: 15 dk)
    private final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(15);

    private final String ISSUER = "security-lab";

    public String generateAccessToken(Authentication authentication) {
        String username = authentication.getName();

        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return buildToken(username, roles, Map.of("type", "access"), ACCESS_TOKEN_TTL);
    }

    public String generateAccessToken(UserDetails userDetails) {
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return buildToken(userDetails.getUsername(), roles, Map.of("type", "access"), ACCESS_TOKEN_TTL);
    }

    private String buildToken(String subject,
                              List<String> roles,
                              Map<String, Object> extraClaims,
                              Duration ttl) {

        Instant now = Instant.now();
        Instant expiresAt = now.plus(ttl);

        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(ISSUER)
                .issuedAt(now)
                .expiresAt(expiresAt)
                .subject(subject)
                .claim("roles", roles);

        extraClaims.forEach(claims::claim);

        JwsHeader jwsHeader = JwsHeader.with(() -> "RS256").build();

        return jwtEncoder.encode(
                JwtEncoderParameters.from(jwsHeader, claims.build())
        ).getTokenValue();
    }

    public String extractUsername(String token) {
        return jwtDecoder.decode(token).getSubject();
    }

    public List<String> extractRoles(String token) {
        Jwt jwt = jwtDecoder.decode(token);
        Object roles = jwt.getClaims().get("roles");
        if (roles instanceof List<?> list) {
            return list.stream().map(Object::toString).collect(Collectors.toList());
        }
        return List.of();
    }

    public boolean isTokenValid(String token) {
        try {
            jwtDecoder.decode(token);
            return true;
        } catch (JwtException ex) {
            return false;
        }
    }
}