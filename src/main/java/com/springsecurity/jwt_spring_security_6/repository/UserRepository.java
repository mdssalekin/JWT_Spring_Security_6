package com.springsecurity.jwt_spring_security_6.repository;

import com.springsecurity.jwt_spring_security_6.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
//    Optional<User> findUserById(Long id);
    //Optional<User> findUserByAddresses
}
