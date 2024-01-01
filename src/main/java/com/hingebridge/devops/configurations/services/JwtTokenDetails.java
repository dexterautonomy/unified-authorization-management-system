package com.hingebridge.devops.configurations.services;

import com.hingebridge.devops.configurations.data.TokenDetail;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

public interface JwtTokenDetails {
    TokenDetail buildTokenDetail(JwtEncodingContext context);
}