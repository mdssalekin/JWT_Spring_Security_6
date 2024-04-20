package com.springsecurity.jwt_spring_security_6.repository;

import com.springsecurity.jwt_spring_security_6.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByRefreshToken(String refreshToken);

    @Query(value = "select rt.* from refresh_token rt " +
            "INNER JOIN users us ON rt.user_id = us.id " +
            "WHERE us.email = :userEmail and (rt.expired = false or rt.revoked = false )", nativeQuery = true)
    List<RefreshToken> findByUserEmailId(@Param("userEmail") String userEmail);
}
