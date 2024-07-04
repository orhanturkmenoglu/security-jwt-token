package com.example.security_jwt.service;

import com.example.security_jwt.dto.LoginMemberRequest;
import com.example.security_jwt.dto.LoginMemberResponse;
import com.example.security_jwt.dto.RegisterMemberRequest;
import com.example.security_jwt.dto.RegisterMemberResponse;
import com.example.security_jwt.mapper.MemberRequestMapper;
import com.example.security_jwt.model.Member;
import com.example.security_jwt.model.Role;
import com.example.security_jwt.model.Token;
import com.example.security_jwt.repository.MemberRepository;
import com.example.security_jwt.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class AuthenticationService {

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;

    public AuthenticationService(JwtService jwtService, AuthenticationManager authenticationManager, MemberRepository memberRepository, PasswordEncoder passwordEncoder, TokenRepository tokenRepository) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.memberRepository = memberRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenRepository = tokenRepository;
    }

    @Transactional
    public LoginMemberResponse loginMember(LoginMemberRequest loginMemberRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginMemberRequest.getUsername(), loginMemberRequest.getPassword()));

        Member member = memberRepository.findMemberByUsername(loginMemberRequest.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("Member not found :" + loginMemberRequest.getUsername()));

        revokeAllTokenByUser(member);

        String generateAccessToken = jwtService.generateAccessToken(member);
        String generateRefreshToken = jwtService.generateRefreshToken(member);

        saveMemberToken(generateAccessToken,generateRefreshToken, member);

        return LoginMemberResponse.builder()
                .accessToken(generateAccessToken)
                .refreshToken(generateRefreshToken)
                .build();
    }

    private void revokeAllTokenByUser(Member member) {
        List<Token> validTokenListByUser = tokenRepository.findAllAccessTokenByUser(member.getId());

        if (!validTokenListByUser.isEmpty()) {
            validTokenListByUser.forEach(t->t.setActive(true));
        }

        tokenRepository.saveAll(validTokenListByUser);
    }

    @Transactional
    public RegisterMemberResponse registerMember(RegisterMemberRequest request) {

        Member tempMember = mapToMember(request);

        Member savedMember = memberRepository.save(tempMember);

        String generateAccessToken = jwtService.generateAccessToken(savedMember);

        String generateRefreshToken = jwtService.generateAccessToken(savedMember);

        saveMemberToken(generateAccessToken,generateRefreshToken, savedMember);

        return new RegisterMemberResponse(generateAccessToken,generateRefreshToken);
    }



    public ResponseEntity refreshToken(HttpServletRequest request, HttpServletResponse response) {

        // yetkilendirme başlığından token çıkar.

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader ==null || !authHeader.startsWith("Bearer ")){
            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        String username = jwtService.extractUserName(token);

        Member member = memberRepository.findMemberByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("No member found"));

        if (jwtService.isValidRefreshToken(token,member)){
            String accessToken = jwtService.generateAccessToken(member);
            String refreshToken = jwtService.generateRefreshToken(member);

            revokeAllTokenByUser(member);
            saveMemberToken(accessToken,refreshToken,member);

            return  new ResponseEntity(new RegisterMemberResponse(accessToken,refreshToken),HttpStatus.OK);
        }

        return  new ResponseEntity(HttpStatus.UNAUTHORIZED);

    }

    private void saveMemberToken(String generateAccessToken,String refreshToken, Member savedMember) {
        Token saveMemberToken = Token.builder()
                .accessToken(generateAccessToken)
                .refreshToken(refreshToken)
                .member(savedMember)
                .isActive(false)
                .build();
        tokenRepository.save(saveMemberToken);
    }

    private Member mapToMember(RegisterMemberRequest request) {
        Member mapToMember = MemberRequestMapper.INSTANCE.mapToMember(request);
        List<Role> roles = new ArrayList<>();
        for (Role role : request.getRoles()) {
            Role tempRole = new Role();
            tempRole.setName(role.getName());
            roles.add(tempRole);
        }
        return mapToMember.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .password(passwordEncoder.encode(request.getPassword()))
                .username(request.getUsername())
                .email(request.getEmail())
                .role(roles)
                .build();
    }
}

