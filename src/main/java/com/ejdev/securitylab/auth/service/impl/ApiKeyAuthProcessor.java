package com.ejdev.securitylab.auth.service.impl;

import com.ejdev.securitylab.auth.dto.AuthRequest;
import com.ejdev.securitylab.auth.dto.AuthResponse;
import com.ejdev.securitylab.auth.service.AuthProcessor;
import com.ejdev.securitylab.security.apikey.ApiKeyService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ApiKeyAuthProcessor implements AuthProcessor {

    private final AuthenticationManager authenticationManager;
    private final ApiKeyService apiKeyService;

    @Override
    public AuthResponse authenticate(AuthRequest request) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                );

        Authentication auth = authenticationManager.authenticate(authToken);
        String apiKey = apiKeyService.issueApiKeyForUser(auth.getName());
        return AuthResponse.forApiKey(apiKey);
    }
}
