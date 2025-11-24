package com.ejdev.securitylab.auth.processor;

import com.ejdev.securitylab.auth.dto.AuthRequest;
import com.ejdev.securitylab.auth.dto.AuthResponse;

public interface AuthProcessor {

    AuthResponse authenticate(AuthRequest request);

    AuthResponse refresh(String refreshToken);
}