package com.example.security_jwt.service;

import com.example.security_jwt.model.Member;
import com.example.security_jwt.model.Role;
import com.example.security_jwt.repository.MemberRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class MemberDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    public MemberDetailsService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Member> member = memberRepository.findMemberByUsername(username);
        if (member.isEmpty()) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        return new User(member.get().getUsername(), member.get().getPassword(), mapToGrantedAuthority(member.get().getRole()));
    }

    public Collection<? extends GrantedAuthority> mapToGrantedAuthority(Collection<Role> roles) {
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }

}
