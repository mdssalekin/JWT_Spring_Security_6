package com.springsecurity.jwt_spring_security_6.service.Impl;

import com.springsecurity.jwt_spring_security_6.entity.RefreshToken;
import com.springsecurity.jwt_spring_security_6.entity.Role;
import com.springsecurity.jwt_spring_security_6.entity.User;
import com.springsecurity.jwt_spring_security_6.mapper.UserMapper;
import com.springsecurity.jwt_spring_security_6.payload.enumeration.TokenType;
import com.springsecurity.jwt_spring_security_6.payload.request.SignUpRequest;
import com.springsecurity.jwt_spring_security_6.payload.response.AuthResponse;
import com.springsecurity.jwt_spring_security_6.payload.response.UserInfoResponse;
import com.springsecurity.jwt_spring_security_6.repository.RefreshTokenRepository;
import com.springsecurity.jwt_spring_security_6.repository.RoleRepository;
import com.springsecurity.jwt_spring_security_6.repository.UserRepository;
import com.springsecurity.jwt_spring_security_6.security.jwt_auth.JwtTokenGenerator;
import com.springsecurity.jwt_spring_security_6.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final JwtTokenGenerator jwtTokenGenerator;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserMapper userMapper;
    private final RoleRepository roleRepository;

    @Override
    public AuthResponse getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse httpServletResponse){
        try {
            var userinfoEntity = userRepository.findByEmail(authentication.getName())
                    .orElseThrow(() -> {
                        log.error("[AuthServiceImpl:userSignInAuth] User :{} not found",authentication.getName());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND ");
                    });
            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);
            saveUserRefreshToken(userinfoEntity, refreshToken);
            createRefreshTokenCookie(httpServletResponse, refreshToken);
            log.info("[AuthServiceImpl:userSignInAuth] Access token for user:{}, has been generated",userinfoEntity.getUserName());
            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(15 * 60)
                    .userName(userinfoEntity.getUserName())
                    .userInfoResponse(new UserInfoResponse(
                            userinfoEntity.getId(),
                            userinfoEntity.getUserName(),
                            userinfoEntity.getEmail(),
                            userinfoEntity.getContactNo()
                    ))
                    .tokenType(TokenType.Bearer)
                    .build();
        } catch (Exception e){
            log.error("[AuthServiceImpl:userSignInAuth]Exception while authenticating the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again");
        }
    }

    @Override
    public Object getAccessTokenUsingRefreshToken(String authorizationHeader){
        if (!authorizationHeader.startsWith(TokenType.Bearer.name())){
            return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please verify your token type!");
        }

        final String refreshToken = authorizationHeader.substring(7);
        var refreshTokenEntity = refreshTokenRepository.findByRefreshToken(refreshToken)
                .filter(tokens -> !tokens.isRevoked())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Refresh token revoked!"));

        User user = refreshTokenEntity.getUser();

        Authentication authentication = createAuthenticationObject(user);
        String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
        return AuthResponse.builder()
                .accessToken(accessToken)
                .accessTokenExpiry(5 * 60)
                .userName(user.getUserName())
                .tokenType(TokenType.Bearer)
                .build();
    }

    @Override
    public AuthResponse registerUser(SignUpRequest signUpRequest, HttpServletResponse httpServletResponse){
        try {
            log.info("[AuthServiceImpl:registerUser]User Registration Started with :::{}",signUpRequest);
            System.out.println("User Registration Info: " + signUpRequest);
            Optional<User> user = userRepository.findByEmail(signUpRequest.getEmail());
            if (user.isPresent()){
                throw new RuntimeException("User already exists!");
            }
            User tempUser = userMapper.convertToEntity(signUpRequest);
            tempUser.setCreatedBy("SELF");
            tempUser.setCreatedAt(LocalDateTime.now());
            Set<String> tempRoles = signUpRequest.getUserRoles();
            Set<Role> roles = new HashSet<>();
            if (tempRoles == null){
                Role userRole = roleRepository.findByName("ROLE_USER")
                        .orElseThrow(
                                () -> new RuntimeException("Error: Role is not found!!")
                        );
                roles.add(userRole);
            } else {
                tempRoles.forEach(role -> {
                    switch (role) {
                        case "admin":
                            Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                                    .orElseThrow(
                                            () -> new RuntimeException("Error: Role is not found!!")
                                    );
                            roles.add(adminRole);
                            break;
                        case "mod":
                            Role modRole = roleRepository.findByName("ROLE_MODERATOR")
                                    .orElseThrow(
                                            () -> new RuntimeException("Error: Role is not found!!")
                                    );
                            roles.add(modRole);
                            break;
                        case "officer":
                            Role accouRole = roleRepository.findByName("ROLE_OFFICER")
                                    .orElseThrow(
                                            () -> new RuntimeException("Error: Role is not found!!")
                                    );
                            roles.add(accouRole);
                            break;
                        default:
                            Role userRole = roleRepository.findByName("ROLE_USER")
                                    .orElseThrow(
                                            () -> new RuntimeException("Error: Role is not found!!")
                                    );
                            roles.add(userRole);
                    }
                });
            }
            tempUser.setRoles(roles);
            Authentication authentication = createAuthenticationObject(tempUser);

            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            User savedUser = userRepository.save(tempUser);
            saveUserRefreshToken(tempUser, refreshToken);
            createRefreshTokenCookie(httpServletResponse, refreshToken);

            log.info("[AuthServiceImpl:registerUser] User:{} Successfully registered",savedUser.getUserName());
            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(5*60)
                    .userName(savedUser.getUserName())
                    .userInfoResponse(new UserInfoResponse(
                            savedUser.getId(),
                            savedUser.getUserName(),
                            savedUser.getEmail(),
                            savedUser.getContactNo()
                    ))
                    .tokenType(TokenType.Bearer)
                    .build();
        } catch (Exception e) {
            log.error("[AuthServiceImpl:registerUser]Exception while registering the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @Override
    public Object revokeRefreshTokensForUser(String userEmail) {
        log.info("Logging out the user:");
        List<RefreshToken> associatedRefreshTokenForUser = refreshTokenRepository.findByUserEmailId(userEmail);
        if (associatedRefreshTokenForUser.isEmpty()){
            System.out.println("Failure");
            return "Failure";
        }
        System.out.println("List of Refresh Token: " + associatedRefreshTokenForUser);

        associatedRefreshTokenForUser.forEach(refreshToken -> {
                    refreshToken.setExpired(true);
                    refreshToken.setRevoked(true);
        });
        refreshTokenRepository.saveAll(associatedRefreshTokenForUser);
        System.out.println("Success");
        return "Success";

    }

    private Authentication createAuthenticationObject(User user){
        String username = user.getEmail();
        String password = user.getPassword();
        List<SimpleGrantedAuthority> authorities = user.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(
                username,
                password, authorities);
    }

    private void saveUserRefreshToken(User user, String refreshToken){
        var refreshTokenEntity = RefreshToken.builder()
                .user(user)
                .refreshToken(refreshToken)
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);
    }

    private Cookie createRefreshTokenCookie(HttpServletResponse response, String refreshToken){
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15*24*60*60);
        response.addCookie(refreshTokenCookie);
        return refreshTokenCookie;
    }
}
