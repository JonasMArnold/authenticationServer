package com.example.auth.entity.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * Converts "GrantedAuthority" Sets to a String that can be saved in a Database.
 */
@Converter
public class GrantedAuthorityConverter implements AttributeConverter<Set<GrantedAuthority>, String> {

    private final String SEPARATOR = ";";

    @Override
    public String convertToDatabaseColumn(Set<GrantedAuthority> authorities) {
        if (authorities == null || authorities.isEmpty()) {
            return "";
        }

        return authorities.stream()
                .map(GrantedAuthority::toString)
                .collect(Collectors.joining(SEPARATOR)); // Use a delimiter
    }

    @Override
    public Set<GrantedAuthority> convertToEntityAttribute(String authoritiesAsString) {
        if (authoritiesAsString == null || authoritiesAsString.isEmpty()) {
            return Collections.emptySet();
        }

        String[] authorityStrings = authoritiesAsString.split(SEPARATOR);
        return Arrays.stream(authorityStrings)
                .map(SimpleGrantedAuthority::new) // Convert strings to SimpleGrantedAuthority objects
                .collect(Collectors.toSet());
    }
}
