package com.example.security_jwt.controller;

import com.example.security_jwt.dto.LoginMemberRequest;
import com.example.security_jwt.dto.LoginMemberResponse;
import com.example.security_jwt.dto.RegisterMemberRequest;
import com.example.security_jwt.dto.RegisterMemberResponse;
import com.example.security_jwt.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterMemberResponse> registerMember(@RequestBody RegisterMemberRequest registerMemberRequest) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authenticationService.registerMember(registerMemberRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginMemberResponse> loginMember(@RequestBody LoginMemberRequest loginMemberRequest) {
        return ResponseEntity.status(HttpStatus.OK).body(authenticationService.loginMember(loginMemberRequest));
    }


    @PostMapping("/refresh_token")
    public ResponseEntity refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        return authenticationService.refreshToken(request,response);
    }
}
