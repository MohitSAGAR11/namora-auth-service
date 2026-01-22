package com.namora.auth_service.dto;

import lombok.Data;

@Data
public class SignInRequest {

    private String email;

    private String password;
}
