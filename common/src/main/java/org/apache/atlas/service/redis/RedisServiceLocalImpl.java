package org.apache.atlas.service.redis;

import org.apache.atlas.AtlasException;
import org.apache.atlas.annotation.ConditionalOnAtlasProperty;
import org.redisson.Redisson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

@Component
@ConditionalOnAtlasProperty(property = "atlas.redis.service.impl")
public class RedisServiceLocalImpl extends AbstractRedisService {

    private static final Logger LOG = LoggerFactory.getLogger(RedisServiceLocalImpl.class);

    @PostConstruct
    public void init() throws AtlasException {
        redisClient = Redisson.create(getLocalConfig());
        LOG.info("Local redis client created successfully.");
    }

    @Override
    public Logger getLogger() {
        return LOG;
    }
}
