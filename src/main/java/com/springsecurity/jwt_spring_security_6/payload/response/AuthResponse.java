package com.springsecurity.jwt_spring_security_6.payload.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.springsecurity.jwt_spring_security_6.payload.enumeration.TokenType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("access_token_expiry")
    private int accessTokenExpiry;

    @JsonProperty("token_type")
    private TokenType tokenType;

    @JsonProperty("user_name")
    private String userName;

    private UserInfoResponse userInfoResponse;

}
