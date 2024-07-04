package com.example.security_jwt.mapper;

import com.example.security_jwt.dto.RegisterMemberRequest;
import com.example.security_jwt.model.Member;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper
public interface MemberRequestMapper {

    MemberRequestMapper  INSTANCE = Mappers.getMapper(MemberRequestMapper.class);

    Member mapToMember(RegisterMemberRequest registerMemberRequest);
}
