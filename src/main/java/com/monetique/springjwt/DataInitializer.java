package com.monetique.springjwt;

import com.monetique.springjwt.models.ERole;
import com.monetique.springjwt.models.Role;
import com.monetique.springjwt.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        // Check and insert ROLE_SUPER_ADMIN if it doesn't exist
        if (!roleExists(ERole.ROLE_SUPER_ADMIN)) {
            Role superAdminRole = new Role();
            superAdminRole.setName(ERole.ROLE_SUPER_ADMIN);
            roleRepository.save(superAdminRole);
            System.out.println("Inserted ROLE_SUPER_ADMIN into the database");
        }

        // Check and insert ROLE_ADMIN if it doesn't exist
        if (!roleExists(ERole.ROLE_ADMIN)) {
            Role adminRole = new Role();
            adminRole.setName(ERole.ROLE_ADMIN);
            roleRepository.save(adminRole);
            System.out.println("Inserted ROLE_ADMIN into the database");
        }

        // Check and insert ROLE_USER if it doesn't exist
        if (!roleExists(ERole.ROLE_USER)) {
            Role userRole = new Role();
            userRole.setName(ERole.ROLE_USER);
            roleRepository.save(userRole);
            System.out.println("Inserted ROLE_USER into the database");
        }
    }

    // Helper method to check if a role exists in the database
    private boolean roleExists(ERole roleName) {
        Optional<Role> role = roleRepository.findByName(roleName);
        return role.isPresent();
    }
}
