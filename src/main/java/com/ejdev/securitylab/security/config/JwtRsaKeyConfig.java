package com.ejdev.securitylab.security.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.Getter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;


@Configuration
public class JwtRsaKeyConfig {

    @Getter
    private final RSAKey rsaKey;

    public JwtRsaKeyConfig() {
        this.rsaKey = generateRsaKey();
    }

    private RSAKey generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("RSA key pair üretilemedi", e);
        }
    }

    @Bean
    public JWKSet jwkSet() {
        return new JWKSet(rsaKey);
    }

    @Bean
    public RSAPublicKey jwtPublicKey() throws JOSEException {
        return rsaKey.toRSAPublicKey();
    }

    @Bean
    public RSAPrivateKey jwtPrivateKey() throws JOSEException {
        return rsaKey.toRSAPrivateKey();
    }
}