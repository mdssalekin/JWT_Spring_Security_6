package com.springsecurity.jwt_spring_security_6.mapper;

import com.springsecurity.jwt_spring_security_6.entity.User;
import com.springsecurity.jwt_spring_security_6.payload.request.SignUpRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserMapper {
    private final PasswordEncoder passwordEncoder;

    public User convertToEntity(SignUpRequest signUpRequest){
        User user = new User();
        user.setUserName(signUpRequest.getUserName());
        user.setEmail(signUpRequest.getEmail());
        user.setContactNo(signUpRequest.getContactNumber());
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        return user;
    }
}
