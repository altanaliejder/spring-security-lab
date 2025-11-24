package com.ejdev.securitylab.auth.service;

import com.ejdev.securitylab.user.entity.UserStatus;
import com.ejdev.securitylab.user.service.CustomUserPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service("authz")
public class AuthorizationService {

    public boolean requireVerifiedEmail(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof CustomUserPrincipal custom)) {
            return false;
        }

        if (custom.getUser().getStatus() != UserStatus.ACTIVE) {
            return false;
        }

        return custom.isEmailVerified();
    }

    public boolean requireUnverifiedEmail(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof CustomUserPrincipal custom)) {
            return false;
        }
        return !custom.isEmailVerified();
    }
}