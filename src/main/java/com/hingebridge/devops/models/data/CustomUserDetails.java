package com.hingebridge.devops.models.data;

import com.hingebridge.devops.models.entities.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CustomUserDetails implements UserDetails {
    private final User user;

    public CustomUserDetails(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorityList = new ArrayList<>();
        for(String authority: user.getAuthorities()) {
            authorityList.add(new SimpleGrantedAuthority(authority));
        }

        return authorityList;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        /*abstract this*/
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        /*abstract this*/
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        /*abstract this*/
        return true;
    }

    @Override
    public boolean isEnabled() {
        /*abstract this*/
        return true;
    }
}