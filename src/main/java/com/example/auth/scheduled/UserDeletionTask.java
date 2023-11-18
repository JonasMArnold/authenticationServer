package com.example.auth.scheduled;

import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.service.UserService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserDeletionTask {

    protected final Log logger = LogFactory.getLog(getClass());

    private final UserService userService;
    private final UserRepository userRepository;


    public UserDeletionTask(UserService userService, UserRepository userRepository) {
        this.userService = userService;
        this.userRepository = userRepository;
    }

    // Run at midnight every day
    @Scheduled(cron = "0 0 0 * * ?")
    public void schedulePermanentDeletion() {
        logger.info("Running user deletion check.");

        List<User> usersToDelete = userRepository.findUsersForPermanentDeletion();

        for (User user : usersToDelete) {
            logger.info("Permanently deleting user: " + user.getUsername());
            userService.deleteUserById(user.getId());
        }
    }
}
