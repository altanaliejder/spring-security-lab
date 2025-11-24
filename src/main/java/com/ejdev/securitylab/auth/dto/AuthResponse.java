package com.ejdev.securitylab.auth.dto;

import com.ejdev.securitylab.auth.strategy.AuthStrategy;

public record AuthResponse(
         String strategy,
         String accessToken,
         String refreshToken,
         String apiKey
) {
    public static AuthResponse forJwt(String accessToken, String refreshToken) {
        return new AuthResponse(AuthStrategy.JWT.name(),accessToken,refreshToken,null);
    }

    public static AuthResponse forApiKey(String apiKey) {
        return new AuthResponse(AuthStrategy.API_KEY.name(),null,null,apiKey);
    }
}
