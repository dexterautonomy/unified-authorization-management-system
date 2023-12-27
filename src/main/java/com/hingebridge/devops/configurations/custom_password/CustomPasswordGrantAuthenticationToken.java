package com.hingebridge.devops.configurations.custom_password;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Set;

public class CustomPasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private String username;
    private String password;
    private String scope;

    protected CustomPasswordGrantAuthenticationToken(String grantType, Authentication authentication, Map<String, Object> extraParams) {
        super(new AuthorizationGrantType(grantType), authentication, extraParams);

        this.username = (String) extraParams.get(OAuth2ParameterNames.USERNAME);
        this.password = (String) extraParams.get(OAuth2ParameterNames.PASSWORD);
        this.scope = (String) extraParams.get(OAuth2ParameterNames.SCOPE);

        if (this.scope == null)
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public Set<String> getScope() {
        return StringUtils.commaDelimitedListToSet(scope.replace(" ", ""));
    }
}