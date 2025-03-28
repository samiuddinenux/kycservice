package com.eunx.kyc.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

public class JwtAuthenticationFilter implements WebFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final String jwtSecret;

    public JwtAuthenticationFilter(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    @Override
        public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String header = exchange.getRequest().getHeaders().getFirst("Authorization");
        logger.debug("Received Authorization header: {}", header);

        if (header == null || !header.startsWith("Bearer "))
            logger.warn("No valid Bearer token found in header");
            return chain.filter(exchange);
        }

        String token = header.substring(7);
        logger.debug("Extracted JWT token: {}", token);

        return Mono.fromCallable(() -> {
            try {
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
                String username = claims.getSubject();
                logger.debug("Parsed username from JWT: {}", username);
                return username;
            } catch (Exception e) {
                logger.error("JWT validation failed: {}", e.getMessage());
                return null;
            }
        }).flatMap(username -> {
            if (username != null) {
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        username, null, Collections.emptyList());
                return chain.filter(exchange)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
            }
            logger.warn("No username extracted from token");
            return chain.filter(exchange);
        });
    }
}