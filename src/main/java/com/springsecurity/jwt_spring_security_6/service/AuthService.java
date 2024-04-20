package com.springsecurity.jwt_spring_security_6.service;

import com.springsecurity.jwt_spring_security_6.payload.request.SignUpRequest;
import com.springsecurity.jwt_spring_security_6.payload.response.AuthResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;

public interface AuthService {
    AuthResponse getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse httpServletResponse);

    Object getAccessTokenUsingRefreshToken(String authorizationHeader);

    AuthResponse registerUser(SignUpRequest signUpRequest, HttpServletResponse httpServletResponse);
    Object revokeRefreshTokensForUser(String userEmail);
}
