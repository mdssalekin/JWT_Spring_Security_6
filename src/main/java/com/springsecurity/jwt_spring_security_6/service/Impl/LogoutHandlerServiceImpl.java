package com.springsecurity.jwt_spring_security_6.service.Impl;


import com.springsecurity.jwt_spring_security_6.payload.enumeration.TokenType;
import com.springsecurity.jwt_spring_security_6.repository.RefreshTokenRepository;
import com.springsecurity.jwt_spring_security_6.security.jwt_auth.RSAKeyRecord;
import com.springsecurity.jwt_spring_security_6.service.LogoutHandlerService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;


@Service
@RequiredArgsConstructor
@Slf4j
public class LogoutHandlerServiceImpl implements LogoutHandlerService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final RSAKeyRecord rsaKeyRecord;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
        if (!authHeader.startsWith(TokenType.Bearer.name() + " ")){
            return;
        }
        System.out.println("Start working");

        final String refreshToken = authHeader.substring(7);
        System.out.println(refreshToken);
        refreshTokenRepository.findByRefreshToken(refreshToken)
                .map(token -> {
                    System.out.println("Token is filtering");
                    token.setUpdatedAt(LocalDateTime.now());
                    token.setUpdatedBy("USER");
                    token.setExpired(true);
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                    return token;
                });
        System.out.println("Logout Successful for Previous code");

        System.out.println(authentication);


    }
}
