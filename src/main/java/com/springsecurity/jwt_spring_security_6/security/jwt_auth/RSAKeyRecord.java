package com.springsecurity.jwt_spring_security_6.security.jwt_auth;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "jwt")
public record RSAKeyRecord(
        RSAPublicKey rsaPublicKey,
        RSAPrivateKey rsaPrivateKey
) {}
