package com.ejdev.securitylab.user.controller;

import com.ejdev.securitylab.user.model.UserDTO;
import com.ejdev.securitylab.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/users")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')") 
public class AdminController {

    private final UserService userService;

    @GetMapping("/{username}")
    public UserDTO getUser(@PathVariable String username) {
        return userService.getUser(username);
    }

    @PostMapping("/{username}/make-admin")
    public UserDTO makeAdmin(@PathVariable String username) {
        return userService.makeAdmin(username);
    }

    @PostMapping("/{username}/block")
    public UserDTO blockUser(@PathVariable String username) {
        return userService.blockUser(username);
    }

    @PostMapping("/{username}/unblock")
    public UserDTO unblockUser(@PathVariable String username) {
        return userService.unblockUser(username);
    }
}