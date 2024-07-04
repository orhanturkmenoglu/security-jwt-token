package com.example.security_jwt.dto;

import com.example.security_jwt.model.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterMemberRequest {

    private String firstName;
    private String lastName;
    private String email;
    private String username;
    private String password;
    private List<Role> roles;

}
