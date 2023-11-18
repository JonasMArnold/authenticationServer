package com.example.auth.cli;

import com.example.auth.service.UserDetailsManagerImpl;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;

@ShellComponent
public class CacheCommand {

    private final UserDetailsManagerImpl userDetailsManager;

    public CacheCommand(UserDetailsManagerImpl userDetailsManager) {
        this.userDetailsManager = userDetailsManager;
    }

    /**
     * Clears user cache
     */
    @ShellMethod(key = "cache cls")
    public String clearCache() {
        userDetailsManager.getUserCache().clear();

        return "Cleared cache";
    }
}
