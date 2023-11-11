package com.example.auth.security;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Used to filter for too many requests from the same person.
 */
public class TimedRepetitionCounter {

    private final Map<String, Integer> counts;
    private final int threshold;
    private final Duration interval;
    private Instant lastClear;

    /**
     * @param interval The time interval in which repetitions are counted
     * @param threshold The maximum number of allowed counts in the time frame
     */
    public TimedRepetitionCounter(Duration interval, int threshold) {
        this.counts = new HashMap<>();
        this.interval = interval;
        this.threshold = threshold;
        this.lastClear = Instant.now();
    }

    /**
     * Checks whether the ip address has been added to the cache during the refresh interval. If the ip address
     * has been added too often already, returns false.
     *
     * @param key the key to be added
     * @return false when key has been added too often in a certain time frame
     */
    public boolean count(String key) {
        Instant now = Instant.now();

        if(now.isAfter(lastClear.plus(this.interval))) {

            // clear and restart counting
            this.counts.clear();
            counts.put(key, 1);
            lastClear = now;
            return true;
        }

        int count = counts.get(key);

        if(count >= threshold) {
            // counted too often
            return false;
        }

        this.counts.put(key, count + 1);
        return true;
    }
}
