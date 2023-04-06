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
package org.apache.atlas.model.apikeys;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown=true)
public class APIKeyRequest {
    // 13 years - This is a tested value on keycloak - on an arbitrally large value on keycloak it starts throwing errors
    private static long MAX_ACCESS_TOKEN_SECONDS = 13 * 365 * 24 * 60 * 60;

    String description = "";
    String displayName;
    List<String> personas = new ArrayList<>(0);
    long validitySeconds;

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        if (StringUtils.isNotEmpty(description)) {
            this.description = description;
        }
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public List<String> getPersonas() {
        return personas;
    }

    public void setPersonas(List<String> personas) {
        this.personas = personas;
    }

    public long getValiditySeconds() {
        return validitySeconds;
    }

    public void setValiditySeconds(long validitySeconds) {
        this.validitySeconds = validitySeconds;
    }
}
