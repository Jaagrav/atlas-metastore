/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.atlas.repository.store.graph.v2.preprocessor.accesscontrol;

import org.apache.atlas.AtlasHeraclesService;
import org.apache.atlas.RequestContext;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.model.apikeys.APIKeyRequest;
import org.apache.atlas.model.apikeys.APIKeyResponse;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasObjectId;
import org.apache.atlas.model.instance.AtlasStruct;
import org.apache.atlas.model.instance.EntityMutations;
import org.apache.atlas.repository.graphdb.AtlasGraph;
import org.apache.atlas.repository.graphdb.AtlasVertex;
import org.apache.atlas.repository.store.bootstrap.AuthPoliciesBootstrapper;
import org.apache.atlas.repository.store.graph.AtlasEntityStore;
import org.apache.atlas.repository.store.graph.v2.AtlasEntityStream;
import org.apache.atlas.repository.store.graph.v2.AtlasGraphUtilsV2;
import org.apache.atlas.repository.store.graph.v2.EntityGraphRetriever;
import org.apache.atlas.repository.store.graph.v2.EntityMutationContext;
import org.apache.atlas.repository.store.graph.v2.preprocessor.PreProcessor;
import org.apache.atlas.repository.store.users.KeycloakStore;
import org.apache.atlas.repository.util.AccessControlUtils;
import org.apache.atlas.type.AtlasTypeRegistry;
import org.apache.atlas.utils.AtlasPerfMetrics;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.apache.atlas.AtlasErrorCode.BAD_REQUEST;
import static org.apache.atlas.repository.Constants.ATTR_ADMIN_USERS;
import static org.apache.atlas.repository.Constants.DESCRIPTION;
import static org.apache.atlas.repository.Constants.DISPLAY_NAME;
import static org.apache.atlas.repository.Constants.NAME;
import static org.apache.atlas.repository.Constants.QUALIFIED_NAME;
import static org.apache.atlas.repository.util.AccessControlUtils.ATTR_POLICY_USERS;
import static org.apache.atlas.repository.util.AccessControlUtils.REL_ATTR_POLICIES;

public class APIKeyPreProcessor implements PreProcessor {
    private static final Logger LOG = LoggerFactory.getLogger(APIKeyPreProcessor.class);

    private final AtlasTypeRegistry typeRegistry;
    private final EntityGraphRetriever entityRetriever;
    private final AtlasGraph graph;
    private final KeycloakStore keycloakStore;
    private final AtlasEntityStore entityStore;
    private final AuthPoliciesBootstrapper bootstrapper;
    private final AtlasHeraclesService heraclesService;

    private List<String> personaQNames = new ArrayList<>(0);
    private List<String> personaGuids = new ArrayList<>(0);

    private static String ATTR_API_KEY_SERVICE_USER_NAME   = "serviceUserName";
    private static String ATTR_API_KEY_SOURCE = "apiKeySource";
    private static String ATTR_API_KEY_CATEGORY = "apiKeyCategory";
    private static String ATTR_API_KEY_CLIENT_ID = "apiKeyClientId";
    private static String ATTR_API_KEY_TOKEN_LIFE = "apiKeyAccessTokenLifespan";
    private static String ATTR_API_KEY_PERMISSIONS = "apiKeyWorkspacePermissions";
    private static String REL_ATTR_API_KEY_ACCESS_PERSONAS = "personas";

    public APIKeyPreProcessor(AtlasTypeRegistry typeRegistry, EntityGraphRetriever entityRetriever,
                              AtlasGraph graph, AtlasEntityStore entityStore) {
        this.typeRegistry = typeRegistry;
        this.entityRetriever = entityRetriever;
        this.graph = graph;
        this.entityStore = entityStore;

        keycloakStore = new KeycloakStore();
        heraclesService = new AtlasHeraclesService();
        bootstrapper = new AuthPoliciesBootstrapper(graph, entityStore, typeRegistry);
    }

    @Override
    public void processAttributes(AtlasStruct entityStruct, EntityMutationContext context, EntityMutations.EntityOperation operation) throws AtlasBaseException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("APIKeyPreProcessor.processAttributes: pre processing {}, {}", entityStruct.getAttribute(QUALIFIED_NAME), operation);
        }

        AtlasEntity entity = (AtlasEntity) entityStruct;

        switch (operation) {
            case CREATE:
                processCreateAPIKey(entity, context.getVertex(entity.getGuid()));
                break;
            case UPDATE:
                processUpdateAPIKey(entity, context.getVertex(entity.getGuid()));
                break;
            default:
                throw new AtlasBaseException(BAD_REQUEST, "Invalid Request");
        }
    }

    private void processCreateAPIKey(AtlasEntity APIKey, AtlasVertex APIKeyVertex) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder recorder = RequestContext.get().startMetricRecord("processCreateAPIKey");

        try {
            String source = (String) APIKey.getAttribute(ATTR_API_KEY_SOURCE);
            String category = (String) APIKey.getAttribute(ATTR_API_KEY_CATEGORY);

            if ("atlan".equals(source) && "internal".equals(category)) {

                List<AtlasEntity> policies = bootstrapper.getAdminPolicies();

                APIKeyResponse response = createKeycloakAndLadonPolicies(APIKey);
                String tokenUserName = response.getAttributes().getAccessToken();

                if (StringUtils.isEmpty(tokenUserName)) {
                    throw new AtlasBaseException(BAD_REQUEST, ATTR_API_KEY_SERVICE_USER_NAME + " for token must be specified");
                }

                for (AtlasEntity policy : policies) {
                    List<String> users = AccessControlUtils.getPolicyUsers(policy);
                    users.add(tokenUserName);
                    policy.setAttribute(ATTR_POLICY_USERS, users);
                }

                AtlasEntityStream stream = new AtlasEntityStream(policies);
                entityStore.createOrUpdate(stream, false);

                List<AtlasObjectId> personas = (List<AtlasObjectId>) APIKey.getRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS);

                if (CollectionUtils.isNotEmpty(personas)) {
                    List<String> userList = Arrays.asList(tokenUserName);

                    for (AtlasObjectId accessControl : personas) {
                        AtlasVertex vertex = entityRetriever.getEntityVertex(accessControl);
                        String qualifiedName = vertex.getProperty(QUALIFIED_NAME, String.class);

                        String role = AccessControlUtils.getPersonaRoleName(qualifiedName);

                        keycloakStore.updateRoleAddUsers(role, userList);
                    }
                }
            }
        } catch (IOException e) {
            throw new AtlasBaseException(e.getMessage());
        } finally {
            RequestContext.get().endMetricRecord(recorder);
        }
    }

    private APIKeyResponse createKeycloakAndLadonPolicies(AtlasEntity apiKey) throws AtlasBaseException {


        APIKeyRequest request = new APIKeyRequest();

        request.setDisplayName((String) apiKey.getAttribute(NAME));
        request.setDescription((String) apiKey.getAttribute(DESCRIPTION));

        if (apiKey.hasAttribute(ATTR_API_KEY_TOKEN_LIFE)) {
            request.setValiditySeconds((Long) apiKey.getAttribute(ATTR_API_KEY_TOKEN_LIFE));
        }

        if (apiKey.hasRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS)) {
            List<AtlasObjectId> personas = (List<AtlasObjectId>) apiKey.getRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS);

            for (AtlasObjectId objectId : personas) {
                if (MapUtils.isNotEmpty(objectId.getUniqueAttributes()) &&
                        StringUtils.isNotEmpty((String) objectId.getUniqueAttributes().get(QUALIFIED_NAME))) {
                    String qName = (String) objectId.getUniqueAttributes().get(QUALIFIED_NAME);
                    personaQNames.add(qName);

                    //AtlasVertex personaVertex = entityRetriever.getEntityVertex(objectId);
                    //personaGuids.add(AtlasGraphUtilsV2.getIdFromVertex(personaVertex));

                } else {

                    AtlasVertex personaVertex = entityRetriever.getEntityVertex(objectId.getGuid());
                    String qName = personaVertex.getProperty(QUALIFIED_NAME, String.class);
                    personaQNames.add(qName);
                    //personaGuids.add(objectId.getGuid());

                }
            }

            request.setPersonas(personaQNames);
        }

        return heraclesService.createAPIToken(request);

    }

    private void processUpdateAPIKey(AtlasEntity APIKey, AtlasVertex existingAPIKey) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder recorder = RequestContext.get().startMetricRecord("processUpdateAPIKey");
        String tokenUserName = (String) APIKey.getAttribute(ATTR_API_KEY_SERVICE_USER_NAME);

        try {
            if (APIKey.hasRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS)) {
                List<AtlasObjectId> newAccessControls = (List<AtlasObjectId>) APIKey.getRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS);

                AtlasEntity existingAPIKeyEntity = entityRetriever.toAtlasEntity(existingAPIKey);
                List<AtlasObjectId> currentAccessControls = (List<AtlasObjectId>) existingAPIKeyEntity.getRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS);

                List<AtlasObjectId> toAdd     = (List<AtlasObjectId>) CollectionUtils.removeAll(newAccessControls, currentAccessControls);
                List<AtlasObjectId> toRemove  = (List<AtlasObjectId>) CollectionUtils.removeAll(currentAccessControls, newAccessControls);

                List<String> userList = Arrays.asList(tokenUserName);

                if (CollectionUtils.isNotEmpty(toAdd)) {
                    for (AtlasObjectId accessControl : toAdd) {
                        AtlasVertex vertex = entityRetriever.getEntityVertex(accessControl);
                        String qualifiedName = vertex.getProperty(QUALIFIED_NAME, String.class);

                        String role = AccessControlUtils.getPersonaRoleName(qualifiedName);

                        keycloakStore.updateRoleAddUsers(role, userList);
                    }
                }

                if (CollectionUtils.isNotEmpty(toRemove)) {
                    for (AtlasObjectId accessControl : toRemove) {
                        AtlasVertex vertex = entityRetriever.getEntityVertex(accessControl);
                        String qualifiedName = vertex.getProperty(QUALIFIED_NAME, String.class);

                        String role = AccessControlUtils.getPersonaRoleName(qualifiedName);

                        keycloakStore.updateRoleRemoveUsers(role, userList);
                    }
                }
            }
        } finally {
            RequestContext.get().endMetricRecord(recorder);
        }
    }
    @Override
    public void processDelete(AtlasVertex vertex) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder recorder = RequestContext.get().startMetricRecord("processDeleteAPIKey");
        AtlasEntity APIKey = entityRetriever.toAtlasEntity(vertex);

        try {
            List<AtlasObjectId> newAccessControls = (List<AtlasObjectId>) APIKey.getRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS);
        } finally {
            RequestContext.get().endMetricRecord(recorder);
        }
    }
}