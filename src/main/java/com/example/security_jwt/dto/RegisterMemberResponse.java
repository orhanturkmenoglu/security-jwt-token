package com.example.security_jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterMemberResponse {

    private String accessToken;
    private String refreshToken;
}
