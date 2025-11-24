package com.ejdev.securitylab.auth.dto;

import com.ejdev.securitylab.auth.strategy.AuthStrategy;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record AuthRequest (
        @NotBlank
        String username,
        @NotBlank
        String password,
        @NotNull
        AuthStrategy strategy
        ){
}