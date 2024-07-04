package com.example.security_jwt.repository;

import com.example.security_jwt.model.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MemberRepository extends JpaRepository<Member,Long> {

   Optional<Member> findMemberByUsername(String userName);

}
