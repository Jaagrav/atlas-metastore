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

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.apache.atlas.ApplicationProperties;
import org.apache.atlas.AtlasException;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.model.apikeys.APIKeyRequest;
import org.apache.atlas.type.AtlasType;
import org.apache.http.client.utils.URIBuilder;
import org.keycloak.KeycloakPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;

@Component
public class HeraclesClient extends AbstractBaseClient {
    private static final Logger LOG = LoggerFactory.getLogger(HeraclesClient.class);

    private static String BASE_URL;

    private static final String BASE_URL_PROPERTY = "heracles.base.url";
    private static final String DEFAULT_BASE_URL = "localhost:5008";

    public void init() {
        try {
            if (httpClient == null) {
                BASE_URL = ApplicationProperties.get().getString(BASE_URL_PROPERTY, DEFAULT_BASE_URL);

                httpClient = new OkHttpClient();
                httpClient.newBuilder()
                        .readTimeout(30000, TimeUnit.MILLISECONDS)
                        .writeTimeout(30000, TimeUnit.MILLISECONDS)
                        .connectTimeout(30000, TimeUnit.MILLISECONDS)
                        .callTimeout(30000, TimeUnit.MILLISECONDS);
            }

        } catch (AtlasException e) {
            e.printStackTrace();
        }
    }

    public URI buildURI(String path) throws AtlasBaseException {
        URI uri = null;

        try {
            uri = new URIBuilder()
                    .setScheme(SCHEME)
                    .setHost(BASE_URL)
                    .setPath(path)
                    .build();
        } catch (URISyntaxException e) {
            throw new AtlasBaseException(e);
        }

        return uri;
    }

    public Request buildRequest(URI uri, APIKeyRequest postData) throws AtlasBaseException {
        Request request = null;

        try {
            String token = ((KeycloakPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getKeycloakSecurityContext().getTokenString();
            Request.Builder builder = new Request.Builder()
                    .url(uri.toURL());

            if (postData != null) {
                builder.post(RequestBody.create(AtlasType.toJson(postData), JSON));
            }

            request = builder.addHeader("Authorization", "Bearer " + token)
                    .build();
        } catch (MalformedURLException e) {
            throw new AtlasBaseException(e);
        }

        return request;
    }

    @PreDestroy
    public void destroy() throws IOException {
        httpClient.dispatcher().executorService().shutdown();
        httpClient.connectionPool().evictAll();
        httpClient.cache().close();
    }
}
