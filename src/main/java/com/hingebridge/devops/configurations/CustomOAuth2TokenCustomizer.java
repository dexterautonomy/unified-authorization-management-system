package com.hingebridge.devops.configurations;

import com.hingebridge.devops.configurations.data.TokenDetail;
import com.hingebridge.devops.configurations.services.impl.TokenDetailBuilder;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    private final TokenDetailBuilder tokenDetailBuilder;

    @Override
    public void customize(JwtEncodingContext context) {
        TokenDetail tokenDetail = tokenDetailBuilder.buildTokenDetail(context);

        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            context
                    .getClaims()
                    .claim("extraDetails", tokenDetailBuilder.buildTokenDetail(context));
        }

        if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            context
                    .getClaims()
                    .claim("scope", tokenDetail.getAuthorities())
                    .claim("extraDetails", tokenDetailBuilder.buildTokenDetail(context));
        }
    }
}