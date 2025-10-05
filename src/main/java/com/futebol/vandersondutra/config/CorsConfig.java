package com.futebol.vandersondutra.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry
            .addMapping("/api/**")
            // Permite chamadas de qualquer origem e também de arquivo (Origin: null)
            .allowedOriginPatterns("*", "null")
            .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .allowedHeaders("Authorization", "Content-Type")
            .exposedHeaders("Authorization")
            .allowCredentials(false)
            .maxAge(3600);
    }
}



