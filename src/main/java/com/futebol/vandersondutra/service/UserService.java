package com.futebol.vandersondutra.service;


import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.futebol.vandersondutra.dto.CreateUserRequest;
import com.futebol.vandersondutra.model.UserAccount;
import com.futebol.vandersondutra.repository.UserRepository;


@Service
public class UserService {

    

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public ResponseEntity<?> createUser(CreateUserRequest body) {
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
