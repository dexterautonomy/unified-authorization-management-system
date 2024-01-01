package com.hingebridge.devops.configurations.data;

import lombok.Builder;
import lombok.Getter;

import java.io.Serializable;
import java.util.Set;

@Getter
@Builder
public class TokenDetail implements Serializable {
    private String school;
    private String faculty;
    private String lastname;
    private String firstname;
    private String username;
    private Set<String> roles;
    private String department;
    private String organization;
    private Set<String> authorities;
    private String applicationName;
}