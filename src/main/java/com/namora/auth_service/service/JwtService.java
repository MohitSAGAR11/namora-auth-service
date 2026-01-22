package com.namora.auth_service.service;

import com.namora.auth_service.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtUtil jwtUtil;

    public String generateAccessToken(String email) {
        return jwtUtil.generateAccessToken(email);
    }

    public String generateRefreshToken(String email) {
        return jwtUtil.generateRefreshToken(email);
    }

    public String extractEmailFromToken(String token) {
        return jwtUtil.extractEmail(token);
    }

    public boolean validateToken(String token) {
        return jwtUtil.validateToken(token);
    }

    public boolean isTokenExpired(String token) {
        return jwtUtil.isTokenExpired(token);
    }

    public Long getAccessTokenExpiration() {
        return jwtUtil.getAccessTokenExpiration();
    }
}