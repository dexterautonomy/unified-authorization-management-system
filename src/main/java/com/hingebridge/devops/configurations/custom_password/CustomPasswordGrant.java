package com.hingebridge.devops.configurations.custom_password;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Set;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.*;

/*
* This class is used to achieve a password grant that has been deprecated in spring boot 3
* */

@Getter
public class CustomPasswordGrant extends OAuth2AuthorizationGrantAuthenticationToken {
    private String scope;
    private String username;
    private String password;

    protected CustomPasswordGrant(String grantType, Authentication authentication, Map<String, Object> extraParams) {
        super(new AuthorizationGrantType(grantType), authentication, extraParams);

        this.username = (String) extraParams.get(USERNAME);
        this.password = (String) extraParams.get(PASSWORD);
        this.scope = (String) extraParams.get(SCOPE);

        if (this.scope == null)
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
    }

    public Set<String> getScope() {
        return StringUtils.commaDelimitedListToSet(scope.replace(" ", ""));
    }
}