/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.atlas.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.atlas.AtlasErrorCode;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;

public abstract class AbstractBaseClient implements BaseClient {
    private static final Logger LOG = LoggerFactory.getLogger(AbstractBaseClient.class);

    protected OkHttpClient httpClient = null;

    public static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    protected static final String SCHEME = "http";
    static final String SCHEME_SECURE = "https";

    @Override
    public <T> T callAPI(Request request, Class<T> responseClass) throws AtlasBaseException {
        if (httpClient == null) {
            throw new AtlasBaseException("client is not initialized");
        }

        try {
            Response response = httpClient.newCall(request).execute();

            if (response.code() == HttpServletResponse.SC_NO_CONTENT) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("<== AtlasAuthRESTClient.sendRequestAndGetResponse(): Not Modified");
                }
                return null;
            } else if (response.code() == HttpServletResponse.SC_OK) {
                String responseBody = response.body().string();
                if (StringUtils.isNotEmpty(responseBody)) {
                    ObjectMapper mapper = new ObjectMapper();
                    return mapper.readValue(responseBody, responseClass);
                } else {
                    LOG.warn("callAPI(): Empty response from Atlas Auth");
                }
            } else {
                LOG.error("callAPI(): HTTP error: " + response.code());
                throw new AtlasBaseException(response.message());
            }
        } catch (Exception e) {
            throw new AtlasBaseException(AtlasErrorCode.BAD_REQUEST, e);
        }
        return null;
    }
}
