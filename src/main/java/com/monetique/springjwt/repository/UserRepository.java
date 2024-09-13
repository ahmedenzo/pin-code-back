package com.monetique.springjwt.repository;

import java.util.Optional;

import com.monetique.springjwt.models.ERole;
import com.monetique.springjwt.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);

  Boolean existsByUsername(String username);
  @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :role")
  Optional<User> findByRole(ERole role);

}
