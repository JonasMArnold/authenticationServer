package com.example.auth.entity;


import jakarta.persistence.*;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.UUID;

/*
TODO: Make this class more integrated. Currently it's only saving the referrer or the reason as a String. It should
    be pre-defined values like an ENUM. Furthermore, there are other good values to save (by whom was it banned, was
    it automatic, temporary ban, etc.)
 */

@Entity
@Table(name = "blacklisted_ips")
@EntityListeners(AuditingEntityListener.class)
public class BlacklistedIP {

    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(
            name = "UUID",
            strategy = "org.hibernate.id.UUIDGenerator"
    )
    private UUID id;

    @Column(unique = true, nullable = false)
    private String ipAddress;

    private String reasonForBlacklisting;

    private String referrer;

    @CreatedDate
    private LocalDateTime createdDate;

    @LastModifiedDate
    private LocalDateTime lastModifiedDate;


    // Constructors
    public BlacklistedIP() {
        // Default constructor for JPA
    }

    public BlacklistedIP(String ipAddress, String reasonForBlacklisting) {
        this.ipAddress = ipAddress;
        this.reasonForBlacklisting = reasonForBlacklisting;
    }


    public UUID getId() {
        return id;
    }

    public String getIpAddress() {
        return ipAddress;
    }
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getReasonForBlacklisting() {
        return reasonForBlacklisting;
    }
    public void setReasonForBlacklisting(String reasonForBlacklisting) {
        this.reasonForBlacklisting = reasonForBlacklisting;
    }

    public String getReferrer() {
        return referrer;
    }
    public void setReferrer(String referrer) {
        this.referrer = referrer;
    }

    public LocalDateTime getCreatedDate() {
        return createdDate;
    }
    public void setCreatedDate(LocalDateTime createdDate) {
        this.createdDate = createdDate;
    }

    public LocalDateTime getLastModifiedDate() {
        return lastModifiedDate;
    }
    public void setLastModifiedDate(LocalDateTime lastModifiedDate) {
        this.lastModifiedDate = lastModifiedDate;
    }

}
