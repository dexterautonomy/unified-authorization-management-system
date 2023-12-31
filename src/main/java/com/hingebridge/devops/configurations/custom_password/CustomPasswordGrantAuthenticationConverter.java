package com.hingebridge.devops.configurations.custom_password;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class CustomPasswordGrantAuthenticationConverter implements AuthenticationConverter {
    private static final String GRANT_TYPE_URN = "password";

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        if(!GRANT_TYPE_URN.equals(grantType))
            return null;

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        MultiValueMap<String, String> requestParams = getParameters(request);
        String password = requestParams.getFirst(OAuth2ParameterNames.PASSWORD);

        if(!StringUtils.hasText(password) || requestParams.get(OAuth2ParameterNames.PASSWORD).size() != 1)
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);

        Map<String, Object> extraParams = new HashMap<>();
        requestParams.forEach((key, value) -> {
            if(!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
            !key.equals(OAuth2ParameterNames.CLIENT_ID))
                extraParams.put(key, value.get(0));
        });

        return new CustomPasswordGrant(password, authentication, extraParams);
    }

    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());

        parameterMap.forEach((key, values) -> {
            if (values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });

        return parameters;
    }
}