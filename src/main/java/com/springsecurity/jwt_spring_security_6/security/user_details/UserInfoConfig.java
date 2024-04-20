package com.springsecurity.jwt_spring_security_6.security.user_details;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.springsecurity.jwt_spring_security_6.entity.Role;
import com.springsecurity.jwt_spring_security_6.entity.User;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
@RequiredArgsConstructor
public class UserInfoConfig implements UserDetails {

    private  final User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles()
                .stream()
                .map(Role::toString)
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
//    private Long id;
//    private String userName;
//    private String email;
//    private String contactNo;
//    @JsonIgnore
//    private String password;
//    private Collection<? extends GrantedAuthority> authorities;
//
//    public UserInfoConfig (
//            Long id,
//            String username,
//            String email,
//            String contactNo,
//            String password,
//            Collection<? extends GrantedAuthority> authorities
//    ){
//        this.id = id;
//        this.userName = username;
//        this.email = email;
//        this.contactNo = contactNo;
//        this.password = password;
//        this.authorities = authorities;
//    }
//    public static UserInfoConfig build(User user){
//        List<GrantedAuthority> authorities = user.getRoles().stream()
//                .map(role -> new SimpleGrantedAuthority(role.getName()))
//                .collect(Collectors.toList());
//        return new UserInfoConfig(
//                user.getId(),
//                user.getUserName(),
//                user.getEmail(),
//                user.getContactNo(),
//                user.getPassword(),
//                authorities);
//    }
//
//    @Override
//    public Collection<? extends GrantedAuthority> getAuthorities() {
//        return authorities;
//    }
//
//    @Override
//    public String getPassword() {
//        return this.password;
//    }
//
//    @Override
//    public String getUsername() {
//        return this.email;
//    }
//
//    @Override
//    public boolean isAccountNonExpired() {
//        return true;
//    }
//
//    @Override
//    public boolean isAccountNonLocked() {
//        return true;
//    }
//
//    @Override
//    public boolean isCredentialsNonExpired() {
//        return true;
//    }
//
//    @Override
//    public boolean isEnabled() {
//        return true;
//    }
}
