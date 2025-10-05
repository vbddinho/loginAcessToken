package com.futebol.vandersondutra.repository;

import com.futebol.vandersondutra.model.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserAccount, Long> {
    Optional<UserAccount> findByEmail(String email);
}



