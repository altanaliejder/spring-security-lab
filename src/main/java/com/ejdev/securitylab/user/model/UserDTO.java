package com.ejdev.securitylab.user.model;

import com.ejdev.securitylab.user.entity.Role;
import com.ejdev.securitylab.user.entity.User;
import com.ejdev.securitylab.user.entity.UserStatus;

import java.util.Set;

public record UserDTO (
        Long id,
        String username,
        String email,
        boolean emailVerified,
        UserStatus status,
        Set<Role> roles
){
    public static UserDTO from(User user) {
        return new UserDTO(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.isEmailVerified(),
                user.getStatus(),
                user.getRoles()
        );
    }
}
