package com.hingebridge.devops;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class UnifiedAuthorizationManagementSystemApplication {
    public static void main(String[] args) {
        SpringApplication.run(UnifiedAuthorizationManagementSystemApplication.class, args);
    }

//    @Bean
//    InMemoryUserDetailsManager inMemoryUserDetailsManager() {
//        var user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .build();
//        return new InMemoryUserDetailsManager(user);
//    }
}