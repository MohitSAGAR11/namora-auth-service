package com.namora.auth_service.service;


import com.namora.auth_service.dto.AuthResponse;
import com.namora.auth_service.dto.RefreshTokenRequest;
import com.namora.auth_service.dto.SignInRequest;
import com.namora.auth_service.dto.SignUpRequest;
import com.namora.auth_service.entity.User;
import com.namora.auth_service.exception.UserAlreadyExistsException;
import com.namora.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Transactional
    public void signUp(SignUpRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("User with email " + request.getEmail() + " already exists");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        userRepository.save(user);
        // return some response
    }

    @Transactional
    public AuthResponse signIn(SignInRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid email or password");
        }

        String accessToken = jwtService.generateAccessToken(user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());
        System.out.println(refreshToken);
        System.out.println(user);
        user.setRefreshToken(refreshToken);
        User savedUser = userRepository.save(user);
        System.out.println(savedUser);

        return new AuthResponse(
                accessToken,
                refreshToken,
                jwtService.getAccessTokenExpiration(),
                user.getEmail()
        );
    }

    @Transactional
    public void logout(String email) {
        // Find user by email, if exists clear the refresh token
        userRepository.findByEmail(email).ifPresent(user -> {
            user.setRefreshToken(null);
            userRepository.save(user);
        });
        // If user doesn't exist or token is already null, logout is still successful
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();

        if (!jwtService.validateToken(refreshToken)) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        if (jwtService.isTokenExpired(refreshToken)) {
            throw new BadCredentialsException("Refresh token has expired");
        }

        String email = jwtService.extractEmailFromToken(refreshToken);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        if (!refreshToken.equals(user.getRefreshToken())) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        String newAccessToken = jwtService.generateAccessToken(user.getEmail());
        String newRefreshToken = jwtService.generateRefreshToken(user.getEmail());

        user.setRefreshToken(newRefreshToken);
        userRepository.save(user);

        return new AuthResponse(
                newAccessToken,
                newRefreshToken,
                jwtService.getAccessTokenExpiration(),
                user.getEmail()
        );
    }
}