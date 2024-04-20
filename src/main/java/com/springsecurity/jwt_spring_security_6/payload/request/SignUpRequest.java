package com.springsecurity.jwt_spring_security_6.payload.request;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.util.Set;

@Data
@RequiredArgsConstructor
public class SignUpRequest {

    private String userName;

    @NotEmpty(message = "User Contact Number must not be empty")
    private String contactNumber;

    private String email;

    private String password;

    private Set<String> userRoles;
}