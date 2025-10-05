package com.futebol.vandersondutra.controller;

import com.futebol.vandersondutra.security.JwtUtil;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(path = "/api/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    public static class LoginRequest {
        @Email
        @NotBlank
        public String email;
        @NotBlank
        public String password;
    }

    @PostMapping(path = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest body) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(body.email, body.password)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails user = (UserDetails) authentication.getPrincipal();
        Map<String, Object> claims = new HashMap<>();
        claims.put("typ", "access");
        String token = jwtUtil.generateToken(user.getUsername(), claims);
        return ResponseEntity.ok(Map.of("token", token));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication authentication) {
        if (authentication == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(Map.of("user", authentication.getName()));
    }
}



