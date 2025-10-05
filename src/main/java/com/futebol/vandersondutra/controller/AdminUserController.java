package com.futebol.vandersondutra.controller;

import com.futebol.vandersondutra.dto.CreateUserRequest;
import com.futebol.vandersondutra.model.Role;
import com.futebol.vandersondutra.model.UserAccount;
import com.futebol.vandersondutra.repository.UserRepository;
import com.futebol.vandersondutra.service.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/admin/users", produces = MediaType.APPLICATION_JSON_VALUE)
public class AdminUserController {


    @Autowired
    private UserService userService;


    

   

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> create(@Valid @RequestBody CreateUserRequest body) {

        return userService.createUser(body);


       
    }
}


