package com.ejdev.securitylab.auth.dto;

import com.ejdev.securitylab.auth.strategy.AuthStrategy;

public record AuthRequest (
        String username,
        String password,
        AuthStrategy strategy
){
}