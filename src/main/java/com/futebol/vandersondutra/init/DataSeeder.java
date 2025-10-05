package com.futebol.vandersondutra.init;

import com.futebol.vandersondutra.model.UserAccount;
import com.futebol.vandersondutra.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.futebol.vandersondutra.model.Role;

@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner seedInitialUser(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.count() == 0) {
                UserAccount user = new UserAccount();
                user.setEmail("admin@local");
                user.setPasswordHash(passwordEncoder.encode("admin123"));
                user.setActive(true);
                user.setRole(Role.ADMIN);
                userRepository.save(user);
            }
        };
    }
}



