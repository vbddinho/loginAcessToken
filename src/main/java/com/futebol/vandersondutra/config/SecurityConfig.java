package com.futebol.vandersondutra.config;

import com.futebol.vandersondutra.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import com.futebol.vandersondutra.security.JwtAuthenticationFilter;
import com.futebol.vandersondutra.security.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public UserDetailsService userDetailsService(UserRepository userRepository) {
		return username -> {
			var user = userRepository.findByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado"));
            var authorities = java.util.List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));
            return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPasswordHash(),
                user.getActive(), true, true, true,
                authorities
            );
		};
	}

	@Bean
	public JwtAuthenticationFilter jwtAuthenticationFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
		return new JwtAuthenticationFilter(jwtUtil, userDetailsService);
	}

    // Removido bean de AuthenticationProvider para evitar uso da API deprecada e
    // permitir que o Spring Security autodetecte ou construa internamente conforme necessário.

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
		http
			// Habilita CORS no filtro de segurança. Mantemos separado e comentado
			// para deixar explícito que o Spring Security usará a configuração do bean
			// `CorsConfigurationSource` abaixo.
			.cors(Customizer.withDefaults())
			.csrf(csrf -> csrf.disable())
			.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.headers(headers -> headers.frameOptions(frame -> frame.disable())) // permitir H2 console
            .authorizeHttpRequests(auth -> auth
                // Permite autenticação e recursos estáticos/raiz
                .requestMatchers("/api/auth/**", "/h2-console/**",  "/login.html","/client.html",  "/", "/static/**","/create_user.html").permitAll()
				// Endpoints públicos da API ficam acessíveis sem token
				.requestMatchers("/api/public/**").permitAll()
                // Área administrativa apenas ADMIN (somente APIs)
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
				// Demais endpoints exigem autenticação via JWT
				.anyRequest().authenticated()
			);
 
		http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration cfg = new CorsConfiguration();
		cfg.setAllowedOriginPatterns(java.util.List.of("*", "null"));
		 // Liste explicitamente seus fronts em produção
		//  cfg.setAllowedOrigins(java.util.List.of(
		// 	"https://app.seudominio.com",
		// 	"https://admin.seudominio.com"
		// ));
		cfg.setAllowedMethods(java.util.List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		cfg.setAllowedHeaders(java.util.List.of("Authorization", "Content-Type"));
		cfg.setExposedHeaders(java.util.List.of("Authorization"));
		cfg.setAllowCredentials(false);
		//cfg.setMaxAge(3600L); // define, em segundos, por quanto tempo o navegador pode “cachear” o resultado da requisição preflight (OPTIONS). Aqui, 3600s = 1 hora. Enquanto o cache valer, o navegador não enviará novos preflights para as mesmas combinações de origem/método/headers, reduzindo latência e tráfego.
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/api/**", cfg);
		return source;
	}
}



