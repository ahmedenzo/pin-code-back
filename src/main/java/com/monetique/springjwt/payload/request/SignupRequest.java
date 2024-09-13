package com.monetique.springjwt.payload.request;

import jakarta.validation.constraints.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequest {
  @NotBlank
  @Size(min = 3, max = 20)
  private String username;


  private String bankname;

  private Set<String> role;

  @NotBlank
  @Size(min = 6, max = 40)
  private String password;



  private Long agencyId;
}
