package com.eunx.kyc.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
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
        // Skip authentication for OPTIONS requests to allow CORS preflight
        if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
            logger.debug("Skipping JWT authentication for OPTIONS request to {}", exchange.getRequest().getPath());
            return chain.filter(exchange);
        }

        String header = exchange.getRequest().getHeaders().getFirst("Authorization");
        logger.debug("Received Authorization header for {} {}: {}",
                exchange.getRequest().getMethod(),
                exchange.getRequest().getPath(),
                header);

        if (header == null || !header.startsWith("Bearer ")) {
            logger.warn("No valid Bearer token found in Authorization header for {} {}",
                    exchange.getRequest().getMethod(),
                    exchange.getRequest().getPath());
            return chain.filter(exchange);
        }

        String token = header.substring(7);
        logger.debug("Extracted JWT token for {} {}: {}",
                exchange.getRequest().getMethod(),
                exchange.getRequest().getPath(),
                token);

        return Mono.fromCallable(() -> {
            try {
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
                String username = claims.getSubject();
                if (username == null) {
                    logger.warn("No subject (username) found in JWT token for {} {}",
                            exchange.getRequest().getMethod(),
                            exchange.getRequest().getPath());
                    return null;
                }
                logger.debug("Parsed username from JWT for {} {}: {}",
                        exchange.getRequest().getMethod(),
                        exchange.getRequest().getPath(),
                        username);
                return username;
            } catch (Exception e) {
                logger.error("JWT validation failed for {} {}: {}",
                        exchange.getRequest().getMethod(),
                        exchange.getRequest().getPath(),
                        e.getMessage());
                return null;
            }
        }).flatMap(username -> {
            if (username != null) {
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        username, null, Collections.emptyList());
                logger.debug("Setting authentication for user {} for {} {}",
                        username,
                        exchange.getRequest().getMethod(),
                        exchange.getRequest().getPath());
                return chain.filter(exchange)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
            }
            logger.warn("No valid username extracted from token for {} {}",
                    exchange.getRequest().getMethod(),
                    exchange.getRequest().getPath());
            return chain.filter(exchange);
        });
    }
}