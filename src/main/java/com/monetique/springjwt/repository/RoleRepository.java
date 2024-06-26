package com.monetique.springjwt.repository;

import java.util.Optional;

import com.monetique.springjwt.models.ERole;
import com.monetique.springjwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
