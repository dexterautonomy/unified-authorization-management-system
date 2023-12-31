package com.hingebridge.devops.services;

import com.hingebridge.devops.models.data.CustomUserDetails;
import com.hingebridge.devops.models.entities.User;
import com.hingebridge.devops.repository.UserRepository;
import com.hingebridge.devops.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> optionalUser = userRepository.findByUsername(username);

        if(!optionalUser.isPresent())
            throw  new UsernameNotFoundException("No User Found");  /*Use a constant*/

        User user = optionalUser.get();
        List<String> activeUserAuthorities = userRoleRepository.getActiveAuthoritiesByUserId(user.getId());
        user.setAuthorities(activeUserAuthorities);

        return new CustomUserDetails(user);
    }
}