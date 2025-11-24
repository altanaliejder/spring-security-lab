package com.ejdev.securitylab.auth.dto;

import com.ejdev.securitylab.auth.strategy.AuthStrategy;
import jakarta.validation.constraints.NotBlank;

public record RegisterRequest (
        @NotBlank
        String username,
        @NotBlank
        String password,
        @NotBlank
        String email
){
}
