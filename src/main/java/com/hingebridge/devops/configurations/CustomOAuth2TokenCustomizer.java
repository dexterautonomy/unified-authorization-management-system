package com.hingebridge.devops.configurations;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

@Component
public class CustomOAuth2TokenCustomizer implements JwtTokenDetails, OAuth2TokenCustomizer<JwtEncodingContext> {
    @Override
    public void customize(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();

        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            Set<String> authorities = principal
                    .getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            context
                    .getClaims()
                    .claim("authorities", authorities)
                    .claim("domain", getDomain())
                    .claim("org", getOrganization())
                    .claim("dept", getDepartment());
        }

        if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            Set<String> authorities = principal
                    .getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            context
                    .getClaims()
                    .claim("authorities", authorities);
        }
    }

    @Override
    public String getDomain() {
        return "null";
    }

    @Override
    public String getDepartment() {
        return "null";
    }

    @Override
    public String getOrganization() {
        return "null";
    }
}