package com.eunx.kyc.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) {
        return http
                .csrf().disable()
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/api/kyc/webhook").permitAll()
                        .pathMatchers("/api/kyc/**").authenticated()
                        .pathMatchers("/api/kyc/user/Uuid").permitAll()
                        .anyExchange().permitAll() .notifyAll()
                )
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtSecret);
    }
}