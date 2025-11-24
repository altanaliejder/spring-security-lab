package com.ejdev.securitylab.user.service;

import com.ejdev.securitylab.auth.dto.RegisterRequest;
import com.ejdev.securitylab.token.service.RefreshTokenService;
import com.ejdev.securitylab.user.entity.Role;
import com.ejdev.securitylab.user.entity.User;
import com.ejdev.securitylab.user.entity.UserStatus;
import com.ejdev.securitylab.user.model.UserDTO;
import com.ejdev.securitylab.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    public User register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Bu kullanıcı adı zaten kullanılıyor.");
        }

        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .email(request.email())
                .emailVerified(false)
                .roles(Set.of(Role.ROLE_USER))
                .status(UserStatus.ACTIVE)
                .build();

        return userRepository.save(user);
    }
    public UserDTO makeAdmin(String username) {
        User user = findUser(username);

        if (user.getRoles().contains(Role.ROLE_ADMIN)) {
            throw new IllegalArgumentException("Kullanıcı zaten ADMIN rolüne sahip.");
        }

        user.getRoles().add(Role.ROLE_ADMIN);
        User saved = userRepository.save(user);
        return UserDTO.from(saved);
    }

    public UserDTO blockUser(String username) {
        User user = findUser(username);

        if (user.getStatus() == UserStatus.BLOCKED) {
            throw new IllegalArgumentException("Kullanıcı zaten engellenmiş.");
        }

        user.setStatus(UserStatus.BLOCKED);
        User saved = userRepository.save(user);

        refreshTokenService.revokeAllTokensOfUser(saved.getId());

        return UserDTO.from(saved);
    }

    public UserDTO unblockUser(String username) {
        User user = findUser(username);

        if (user.getStatus() != UserStatus.BLOCKED) {
            throw new IllegalArgumentException("Kullanıcı engelli değil.");
        }

        user.setStatus(UserStatus.ACTIVE);
        User saved = userRepository.save(user);
        return UserDTO.from(saved);
    }

    public UserDTO getUser(String username) {
        User user = findUser(username);
        return UserDTO.from(user);
    }

    private User findUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Kullanıcı bulunamadı: " + username));
    }
}