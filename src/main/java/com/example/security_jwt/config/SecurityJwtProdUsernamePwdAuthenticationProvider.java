package com.example.security_jwt.config;

import com.example.security_jwt.service.MemberDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@Profile("prod")
@RequiredArgsConstructor
public class SecurityJwtProdUsernamePwdAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;

    private final MemberDetailsService memberDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
       String username = authentication.getName();
       String password = String.valueOf(authentication.getCredentials());

        UserDetails userDetails = memberDetailsService.loadUserByUsername(username);

        if (passwordEncoder.matches(password,userDetails.getPassword())){
            int hour = LocalDateTime.now().getHour();
            if (hour==12){
                throw new BadCredentialsException("Sistem öğlen arasında devre dışı");
            }
            return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
        }else {
            throw new BadCredentialsException("Geçersiz şifre");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
