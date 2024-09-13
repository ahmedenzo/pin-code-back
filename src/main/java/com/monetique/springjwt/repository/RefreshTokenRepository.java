package com.monetique.springjwt.repository;



import com.monetique.springjwt.models.RefreshToken;
import com.monetique.springjwt.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    Optional<RefreshToken> findByUser(User user);
    void deleteByUser(User user);
    Optional<RefreshToken> findByUserId(Long userId);
}
