package com.ejdev.securitylab.security.apikey;

import com.ejdev.securitylab.user.entity.User;
import com.ejdev.securitylab.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ApiKeyService {

    private final UserRepository userRepository;

    @Transactional
    public String issueApiKeyForUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found: " + username));

        if (user.getApiKey() == null) {
            user.setApiKey(generateApiKey());
            userRepository.save(user);
        }

        return user.getApiKey();
    }

    public String generateApiKey() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}