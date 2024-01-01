package com.hingebridge.devops.configurations.services.impl;

import com.hingebridge.devops.configurations.services.JwtTokenDetails;
import com.hingebridge.devops.configurations.data.TokenDetail;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
public class TokenDetailBuilder implements JwtTokenDetails {
    @Override
    public TokenDetail buildTokenDetail(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();

        Set<String> authorities = principal
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        TokenDetail tokenDetail = TokenDetail
                .builder()
                .authorities(authorities)
                .username(principal.getName())
                .build();

        return tokenDetail;
    }
}