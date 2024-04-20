package com.springsecurity.jwt_spring_security_6.security.jwt_auth;

import com.springsecurity.jwt_spring_security_6.repository.UserRepository;
import com.springsecurity.jwt_spring_security_6.security.user_details.UserInfoConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class JwtTokenUtils {
    private final UserRepository userRepository;

    public String getUsername(Jwt jwtToken){
        return jwtToken.getSubject();
    }

    public boolean isTokenValid(Jwt jwtToken, UserDetails userDetails){
        final String username = getUsername(jwtToken);
        boolean isTokenExpired = getIfTokenIsExpired(jwtToken);
        boolean isTokenUserSameAsDataBase=username.equals(userDetails.getUsername());
        return !isTokenExpired && isTokenUserSameAsDataBase;
    }

    public boolean getIfTokenIsExpired(Jwt jwtToken){
        return Objects.requireNonNull(jwtToken.getExpiresAt()).isBefore(Instant.now());
    }

    public UserDetails userDetails(String email){
        return userRepository.findByEmail(email)
                .map(UserInfoConfig::new)
                .orElseThrow(() -> new UsernameNotFoundException("UserEmail: " + email + " does not exist!"));
    }
}
