package com.hingebridge.devops.models.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.Data;

import java.io.Serializable;
import java.util.Collection;

@Data
@Entity
@Table(name = "user")
public class User extends BaseProps implements Serializable {
    private String lastname;
    private String username;
    private String firstname;
    @Lob
    private String password;
    @Transient
    private Collection<String> authorities;
}