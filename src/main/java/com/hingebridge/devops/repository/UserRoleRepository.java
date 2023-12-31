package com.hingebridge.devops.repository;

import com.hingebridge.devops.models.entities.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, Long> {
    @Query("SELECT role.name FROM UserRole userRole " +
            "INNER JOIN Role role " +
            "ON userRole.roleId = role.id " +
            "WHERE userRole.userId = :userId " +
            "AND userRole.status = true " +
            "AND role.status = true")
    List<String> getActiveAuthoritiesByUserId(@Param("userId") Long userId);
}