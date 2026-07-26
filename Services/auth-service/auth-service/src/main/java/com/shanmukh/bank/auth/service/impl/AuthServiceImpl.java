package com.shanmukh.bank.auth.service.impl;

import com.shanmukh.bank.auth.dto.AuthResponse;
import com.shanmukh.bank.auth.dto.LoginRequest;
import com.shanmukh.bank.auth.dto.RegisterRequest;
import com.shanmukh.bank.auth.entity.User;
import com.shanmukh.bank.auth.enums.Role;
import com.shanmukh.bank.auth.exception.UserAlreadyExistsException;
import com.shanmukh.bank.auth.repository.UserRepository;
import com.shanmukh.bank.auth.security.JwtService;
import com.shanmukh.bank.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Override
    public AuthResponse register(RegisterRequest request) {

        log.info("Registration request received for email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Registration failed. Email already exists: {}", request.getEmail());
            throw new UserAlreadyExistsException("Email already exists");
        }

        if (userRepository.existsByMobileNumber(request.getMobileNumber())) {
            log.warn("Registration failed. Mobile number already exists: {}", request.getMobileNumber());
            throw new RuntimeException("Mobile number already exists");
        }

        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .mobileNumber(request.getMobileNumber())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.CUSTOMER)
                .build();

        userRepository.save(user);

        log.info("User registered successfully with email: {}", request.getEmail());

        return AuthResponse.builder()
                .message("User Registered Successfully")
                .build();
    }

    @Override
    public AuthResponse login(LoginRequest request) {

        log.info("Login request received for email: {}", request.getEmail());

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        String token = jwtService.generateToken(request.getEmail());

        log.info("JWT generated successfully for email: {}", request.getEmail());

        return AuthResponse.builder()
                .token(token)
                .message("Login Successful")
                .build();
    }
}