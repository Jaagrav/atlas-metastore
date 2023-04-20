package org.apache.atlas.service.redis;

import org.apache.atlas.AtlasException;
import org.slf4j.Logger;

public interface RedisService {

  boolean acquireDistributedLock(String key) throws AtlasException;

  void releaseDistributedLock(String key);

  Logger getLogger();

}
