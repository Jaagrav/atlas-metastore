package org.apache.atlas.service.redis;

import org.apache.atlas.ApplicationProperties;
import org.apache.atlas.AtlasException;
import org.apache.commons.configuration.Configuration;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.redisson.config.ReadMode;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public abstract class AbstractRedisService implements RedisService {

    private static final String REDIS_URL_PREFIX = "redis://";
    private static final String ATLAS_REDIS_URL = "atlas.redis.url";
    private static final String ATLAS_REDIS_SENTINEL_URLS = "atlas.redis.sentinel.urls";
    private static final String ATLAS_REDIS_USERNAME = "atlas.redis.username";
    private static final String ATLAS_REDIS_PASSWORD = "atlas.redis.password";
    private static final String ATLAS_REDIS_MASTER_NAME = "atlas.redis.master_name";
    private static final String ATLAS_REDIS_LOCK_WAIT_TIME_MS = "atlas.redis.lock.wait_time.ms";
    private static final String ATLAS_REDIS_LEASE_TIME_MS = "atlas.redis.lock.lease_time.ms";
    private static final int DEFAULT_REDIS_WAIT_TIME_MS = 15000;
    private static final int DEFAULT_REDIS_LEASE_TIME_MS = 60000;

    RedissonClient redisClient;
    Map<String, RLock> keyLockMap;
    Configuration atlasConfig;
    long waitTimeInMS;
    long leaseTimeInMS;

    private void initAtlasConfig() throws AtlasException {
        keyLockMap = new ConcurrentHashMap<>();
        atlasConfig = ApplicationProperties.get();
        waitTimeInMS = atlasConfig.getLong(ATLAS_REDIS_LOCK_WAIT_TIME_MS, DEFAULT_REDIS_WAIT_TIME_MS);
        leaseTimeInMS = atlasConfig.getLong(ATLAS_REDIS_LEASE_TIME_MS, DEFAULT_REDIS_LEASE_TIME_MS);
    }

    Config getLocalConfig() throws AtlasException {
        initAtlasConfig();
        Config config = new Config();
        config.useSingleServer()
                .setAddress(atlasConfig.getString(ATLAS_REDIS_URL))
                .setUsername(atlasConfig.getString(ATLAS_REDIS_USERNAME))
                .setPassword(atlasConfig.getString(ATLAS_REDIS_PASSWORD));
        return config;
    }

    Config getProdConfig() throws AtlasException {
        initAtlasConfig();
        Config config = new Config();
        config.useSentinelServers()
                .setReadMode(ReadMode.MASTER_SLAVE)
                .setMasterName(atlasConfig.getString(ATLAS_REDIS_MASTER_NAME))
                .addSentinelAddress(formatSentinelUrls(atlasConfig.getStringArray(ATLAS_REDIS_SENTINEL_URLS)))
                .setUsername(atlasConfig.getString(ATLAS_REDIS_USERNAME))
                .setPassword(atlasConfig.getString(ATLAS_REDIS_PASSWORD));
        return config;
    }

    private String[] formatSentinelUrls(String[] urls) {
        return Arrays.stream(urls).map(url -> {
            if (url.startsWith(REDIS_URL_PREFIX)) {
                return url;
            }
            return REDIS_URL_PREFIX + url;
        }).collect(Collectors.toList()).stream().toArray(String[]::new);
    }

    @Override
    public boolean acquireDistributedLock(String key) throws AtlasException {
        getLogger().info("Attempting to acquire distributed lock for {}", key);
        boolean isLockAcquired;
        try {
            RLock lock = redisClient.getFairLock(key);
            isLockAcquired = lock.tryLock(waitTimeInMS, leaseTimeInMS, TimeUnit.MILLISECONDS);
            if (isLockAcquired) {
                keyLockMap.put(key, lock);
                getLogger().info("Acquired distributed lock on task for {}", key);
            } else {
                getLogger().info("Attempt failed as lock {} is already acquired.", key);
            }
        } catch (InterruptedException e) {
            getLogger().error("Failed to acquire distributed lock.", e);
            throw new AtlasException(e);
        }
        return isLockAcquired;
    }

    @Override
    public void releaseDistributedLock(String key) {
        if (!keyLockMap.containsKey(key)) {
            return;
        }
        try {
            RLock lock = keyLockMap.get(key);
            if (lock.isHeldByCurrentThread()) {
                getLogger().info("Attempt to release distributed lock for {}", key);
                lock.unlock();
                getLogger().info("successfully released distributed lock for {}", key);
            }
        } catch (Exception e) {
            getLogger().error("Failed to release distributed lock for {}", key, e);
        }
    }
}
