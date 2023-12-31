package com.hingebridge.devops.models.entities;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;

@Data
@MappedSuperclass
public class CommonFields implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @JsonFormat(pattern = "yyyy/mm/dd")
    @Temporal(TemporalType.TIMESTAMP)
    private Date createdOn = new Date();
    @JsonFormat(pattern = "yyyy/mm/dd")
    @Temporal(TemporalType.TIMESTAMP)
    private Date verifiedOn = new Date();;
    @JsonFormat(pattern = "yyyy/mm/dd")
    @Temporal(TemporalType.TIMESTAMP)
    private Date updatedOn = new Date();;
    protected Boolean status = false;
}