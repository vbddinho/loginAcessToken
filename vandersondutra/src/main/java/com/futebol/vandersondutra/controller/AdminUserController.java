package com.futebol.vandersondutra.controller;

import com.futebol.vandersondutra.model.Role;
import com.futebol.vandersondutra.model.UserAccount;
import com.futebol.vandersondutra.repository.UserRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/admin/users", produces = MediaType.APPLICATION_JSON_VALUE)
public class AdminUserController {

    public static class CreateUserRequest {
        @Email
        @NotBlank
        public String email;
        @NotBlank
        public String password;
        @NotNull
        public Role role;
        public Boolean active = true;
    }

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AdminUserController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> create(@Valid @RequestBody CreateUserRequest body) {
        if (userRepository.findByEmail(body.email).isPresent()) {
            return ResponseEntity.status(409).body(java.util.Map.of("error", "Email já cadastrado"));
        }
        UserAccount u = new UserAccount();
        u.setEmail(body.email.trim().toLowerCase());
        u.setPasswordHash(passwordEncoder.encode(body.password));
        u.setRole(body.role);
        u.setActive(body.active != null ? body.active : true);
        userRepository.save(u);
        return ResponseEntity.ok(java.util.Map.of("id", u.getId(), "email", u.getEmail(), "role", u.getRole().name()));
    }
}


