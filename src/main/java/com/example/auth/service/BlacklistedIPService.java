package com.example.auth.service;


import com.example.auth.entity.BlacklistedIP;
import com.example.auth.repository.BlacklistedIPRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Service layer for handling operations related to blacklisted IP addresses.
 */
@Service
public class BlacklistedIPService {

    private final BlacklistedIPRepository repository;

    /**
     * Regex pattern to match valid IPv6 addresses.
     */
    private static final Pattern IPV6_PATTERN =
            Pattern.compile("([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})");

    /**
     * Constructor for dependency injection of the BlacklistedIPRepository.
     *
     * @param repository The repository to access blacklisted IP data.
     */
    @Autowired
    public BlacklistedIPService(BlacklistedIPRepository repository) {
        this.repository = repository;
    }

    /**
     * Retrieves all the blacklisted IPs stored in the database.
     *
     * @return A list of blacklisted IPs.
     */
    public List<BlacklistedIP> getAllBlacklistedIPs() {
        return repository.findAll();
    }

    /**
     * Blacklists an IP address with a given reason.
     * Validates the IP format before adding to the blacklist.
     *
     * @param ipAddress The IP address to blacklist.
     * @param reason    The reason for blacklisting the IP.
     * @return The blacklisted IP object after being saved to the database.
     */
    public BlacklistedIP blacklistIP(String ipAddress, String reason) {
        validateIPv6Format(ipAddress);
        BlacklistedIP ip = new BlacklistedIP(ipAddress, reason);
        return repository.save(ip);
    }

    /**
     * Updates an existing blacklisted IP's address and reason.
     *
     * @param originalIpAddress The original blacklisted IP address.
     * @param updatedIpAddress  The new IP address to replace the original.
     * @param updatedReason     The new reason for blacklisting.
     */
    public void updateBlacklistedIP(String originalIpAddress, String updatedIpAddress, String updatedReason) {
        BlacklistedIP originalIP = getBlacklistedIPByAddress(originalIpAddress);

        validateIPv6Format(updatedIpAddress);

        originalIP.setIpAddress(updatedIpAddress);
        originalIP.setReasonForBlacklisting(updatedReason);
        repository.save(originalIP);
    }

    /**
     * Removes an IP address from the blacklist.
     *
     * @param ipAddress The IP address to be removed from the blacklist.
     */
    public void removeBlacklistedIPByAddress(String ipAddress) {
        BlacklistedIP ip = getBlacklistedIPByAddress(ipAddress);
        repository.deleteById(ip.getId());
    }

    /**
     * Retrieves a blacklisted IP entity by its address.
     * Throws an exception if the IP is not found in the database.
     *
     * @param ipAddress The IP address to search for.
     * @return The found blacklisted IP entity.
     */
    private BlacklistedIP getBlacklistedIPByAddress(String ipAddress) {
        return repository.findByIpAddress(ipAddress)
                .orElseThrow(() -> new IllegalArgumentException("IP not found in database"));
    }


    /**
     * Fetches a BlacklistedIP object by its IP address.
     *
     * @param ipAddress The IP address to be searched for.
     * @return An Optional containing the BlacklistedIP if found, or an empty Optional otherwise.
     */
    public Optional<BlacklistedIP> findByIpAddress(String ipAddress) {
        return repository.findByIpAddress(ipAddress);
    }


    /**
     * Validates that the given IP address matches the IPv6 format.
     * Throws an exception if the format is invalid.
     *
     * @param ipAddress The IP address to validate.
     */
    private void validateIPv6Format(String ipAddress) {
        if (!isValidIPv6(ipAddress)) {
            throw new IllegalArgumentException("Invalid IPv6 format");
        }
    }

    /**
     * Checks if the given IP address is a valid IPv6 format.
     *
     * @param ipAddress The IP address to check.
     * @return True if the IP address matches the IPv6 format, false otherwise.
     */
    private boolean isValidIPv6(String ipAddress) {
        return IPV6_PATTERN.matcher(ipAddress).matches();
    }
}
