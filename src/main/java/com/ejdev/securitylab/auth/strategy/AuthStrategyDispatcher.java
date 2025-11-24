package com.ejdev.securitylab.auth.strategy;

import com.ejdev.securitylab.auth.dto.AuthRequest;
import com.ejdev.securitylab.auth.dto.AuthResponse;
import com.ejdev.securitylab.auth.service.AuthProcessor;
import com.ejdev.securitylab.auth.service.impl.ApiKeyAuthProcessor;
import com.ejdev.securitylab.auth.service.impl.JwtAuthProcessor;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.EnumMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthStrategyDispatcher {

    private final JwtAuthProcessor jwtAuthProcessor;
    private final ApiKeyAuthProcessor apiKeyAuthProcessor;

    private Map<AuthStrategy, AuthProcessor> processorMap;

    private Map<AuthStrategy, AuthProcessor> getProcessorMap() {
        if (processorMap == null) {
            processorMap = new EnumMap<>(AuthStrategy.class);
            processorMap.put(AuthStrategy.JWT, jwtAuthProcessor);
            processorMap.put(AuthStrategy.API_KEY, apiKeyAuthProcessor);
        }
        return processorMap;
    }

    public AuthResponse authenticate(AuthRequest request) {
        if (request.strategy() == null) {
            throw new IllegalArgumentException("Auth strategy is required");
        }

        AuthProcessor processor = getProcessorMap().get(request.strategy());
        if (processor == null) {
            throw new IllegalArgumentException(
                    "Unsupported auth strategy: " + request.strategy());
        }

        return processor.authenticate(request);
    }
}
