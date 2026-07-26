package com.shanmukh.bank.auth.service;

import com.shanmukh.bank.auth.dto.AuthResponse;
import com.shanmukh.bank.auth.dto.LoginRequest;
import com.shanmukh.bank.auth.dto.RegisterRequest;

public interface AuthService {

    AuthResponse register(RegisterRequest request);

    AuthResponse login(LoginRequest request);

}