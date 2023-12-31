package com.hingebridge.devops.models.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "user_role")
public class UserRole extends CommonFields {
    private Long userId;
    private Long roleId;
}