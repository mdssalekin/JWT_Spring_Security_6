package com.springsecurity.jwt_spring_security_6;

import com.springsecurity.jwt_spring_security_6.security.jwt_auth.RSAKeyRecord;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RSAKeyRecord.class)
@SpringBootApplication
public class JwtSpringSecurity6Application {

    public static void main(String[] args) {
        SpringApplication.run(JwtSpringSecurity6Application.class, args);
    }

}
