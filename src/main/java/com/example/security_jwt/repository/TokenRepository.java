package com.example.security_jwt.repository;

import com.example.security_jwt.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {

    @Query(
            """
                            select t from Token t inner join Member m on 
                            t.member.id = m.id 
                            where t.member.id = :userId
                    """
    )
    List<Token> findAllAccessTokenByUser(Long userId);

    Optional<Token> findByAccessToken(String token);

    Optional<Token> findByRefreshToken(String token);
}