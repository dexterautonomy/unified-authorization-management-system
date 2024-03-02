package com.hingebridge.devops.models.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Data;

import java.io.Serializable;

@Data
@Entity
@Table(name = "role")
public class Role extends BaseProps implements Serializable {
    private String name;
}