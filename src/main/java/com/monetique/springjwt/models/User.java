package com.monetique.springjwt.models;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.HashSet;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "username")
        })
public class User {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @NotBlank
  @Size(max = 20)
  private String username;

  @NotBlank
  @Size(max = 120)
  private String password;

  @NotBlank
  @Size(max = 50)
  private String bankname;
  public User(String username, String password, String bankname, Set<Role> roles) {
    this.username = username;
    this.password = password;
    this.bankname = bankname;
    this.roles = roles;
  }

  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(name = "user_roles",
          joinColumns = @JoinColumn(name = "user_id"),
          inverseJoinColumns = @JoinColumn(name = "role_id"))
  private Set<Role> roles = new HashSet<>();
}