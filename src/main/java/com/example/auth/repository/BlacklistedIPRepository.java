package com.example.auth.repository;


import com.example.auth.entity.BlacklistedIP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface BlacklistedIPRepository extends JpaRepository<BlacklistedIP, UUID> {
    Optional<BlacklistedIP> findByIpAddress(String ipAddress);
}
