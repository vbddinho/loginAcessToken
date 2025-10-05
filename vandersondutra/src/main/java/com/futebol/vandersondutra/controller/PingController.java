package com.futebol.vandersondutra.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping(path = "/api", produces = MediaType.TEXT_PLAIN_VALUE)
public class PingController {

    @GetMapping("/ping")
    public String ping() {
        return "Olá do backend Spring!";
    }

    // Endpoint público de exemplo, não exige token
    @GetMapping("/public/hello")
    public String publicHello() {
        return "Olá público! Este endpoint não requer autenticação.";
    }

    // Endpoint protegido de exemplo, exige token válido (config via SecurityConfig)
    @GetMapping("/protected/hello")
    public String protectedHello(@RequestHeader(name = "Authorization", required = false) String authorization) {
        return "Olá protegido! Seu token foi aceito.";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/ping")
    public String adminPing() {
        return "pong admin";
    }
}



