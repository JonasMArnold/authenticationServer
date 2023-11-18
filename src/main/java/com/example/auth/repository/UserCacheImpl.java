package com.example.auth.repository;

import com.example.auth.entity.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;
import java.util.Queue;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * In memory cache for user objects. Uses leas
 */
public class UserCacheImpl {

    protected final Log logger = LogFactory.getLog(getClass());

    private static final int MAX_SIZE = 1 << 16;

    private final Map<UUID, User> byID = new HashMap<>(MAX_SIZE);
    private final Map<String, User> byUsername = new HashMap<>(MAX_SIZE);

    private final Queue<UUID> idQueue = new LinkedBlockingQueue<>(MAX_SIZE);

    /**
     * Get user from Cache by id
     * @param id id
     * @return user or null if cache miss
     */
    public User get(UUID id) {
        Assert.notNull(id, "Id can't be null");

        User user = byID.get(id);

        if(user == null) {
            logger.trace("Cache miss " + id);
        } else {
            logger.trace("Cache hit " + id);
        }

        return user;
    }

    /**
     * Get user from Cache by username
     * @param username username
     * @return user or null if cache miss
     */
    public User get(String username) {
        Assert.notNull(username, "Username can't be null");

        User user = byUsername.get(username);

        if(user == null) {
            logger.trace("Cache miss " + username);
        } else {
            logger.trace("Cache hit " + username);
        }

        return user;
    }

    /**
     * Returns the number of entries in the cache
     */
    public int size() {
        return this.byID.size();
    }

    /**
     * Stores user in cache
     * @param user user
     */
    public void put(User user) {
        Assert.notNull(user, "User can't be null");
        Assert.notNull(user.getId(), "Id can't be null");
        Assert.notNull(user.getUsername(), "Username can't be null");

        if (this.size() >= MAX_SIZE) {

            // the id queue still stores removed ids
            while(true) {
                UUID id = this.idQueue.poll();

                // check if ID has already been evicted
                if(byID.containsKey(id)) {
                    this.evict(id);
                    break;
                }
            }
        }

        byID.put(user.getId(), user);
        byUsername.put(user.getUsername(), user);
        this.idQueue.add(user.getId());
    }

    /**
     * Remove user from Cache by id
     * @param id id
     */
    public void evict(UUID id) {
        Assert.notNull(id, "Id can't be null");
        User user = byID.remove(id);

        if (user != null) {
            byUsername.remove(user.getUsername());
        }
    }

    /**
     * Remove user from Cache by username
     * @param username username
     */
    public void evict(String username) {
        Assert.notNull(username, "Username can't be null");
        User user = byUsername.remove(username);

        if (user != null) {
            byID.remove(user.getId());
        }
    }

    /**
     * Clears entire cache
     */
    public void clear() {
        this.byID.clear();
        this.byUsername.clear();
    }
}
