package com.futebol.vandersondutra.dto;

import com.futebol.vandersondutra.model.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class CreateUserRequest {
    @Email
        @NotBlank
        public String email;
        @NotBlank
        public String password;
        @NotNull
        public Role role;
        public Boolean active = true;
}
