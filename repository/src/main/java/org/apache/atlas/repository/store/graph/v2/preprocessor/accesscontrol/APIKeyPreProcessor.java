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
import org.apache.atlas.discovery.EntityDiscoveryService;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.model.apikeys.APIKeyAttributes;
import org.apache.atlas.model.apikeys.APIKeyRequest;
import org.apache.atlas.model.apikeys.APIKeyResponse;
import org.apache.atlas.model.discovery.AtlasSearchResult;
import org.apache.atlas.model.discovery.IndexSearchParams;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasEntityHeader;
import org.apache.atlas.model.instance.AtlasObjectId;
import org.apache.atlas.model.instance.AtlasRelatedObjectId;
import org.apache.atlas.model.instance.AtlasRelationship;
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
import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.apache.atlas.AtlasErrorCode.BAD_REQUEST;
import static org.apache.atlas.AtlasErrorCode.OPERATION_NOT_SUPPORTED;
import static org.apache.atlas.repository.Constants.ATTR_ADMIN_USERS;
import static org.apache.atlas.repository.Constants.DESCRIPTION;
import static org.apache.atlas.repository.Constants.DISPLAY_NAME;
import static org.apache.atlas.repository.Constants.NAME;
import static org.apache.atlas.repository.Constants.POLICY_ENTITY_TYPE;
import static org.apache.atlas.repository.Constants.QUALIFIED_NAME;
import static org.apache.atlas.repository.util.AccessControlUtils.ATTR_POLICY_USERS;
import static org.apache.atlas.repository.util.AccessControlUtils.getPersonaRoleName;
import static org.apache.atlas.repository.util.AccessControlUtils.getUUID;
import static org.apache.atlas.util.AtlasEntityUtils.mapOf;

public class APIKeyPreProcessor implements PreProcessor {
    private static final Logger LOG = LoggerFactory.getLogger(APIKeyPreProcessor.class);

    private final AtlasTypeRegistry typeRegistry;
    private final EntityGraphRetriever entityRetriever;
    private final AtlasGraph graph;
    private final KeycloakStore keycloakStore;
    private final AtlasEntityStore entityStore;
    private final EntityDiscoveryService discoveryService;
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

    public APIKeyPreProcessor(AtlasGraph graph, AtlasTypeRegistry typeRegistry,
                              EntityGraphRetriever entityRetriever, EntityDiscoveryService discoveryService,
                               AtlasEntityStore entityStore) {
        this.typeRegistry = typeRegistry;
        this.entityRetriever = entityRetriever;
        this.graph = graph;
        this.entityStore = entityStore;
        this.discoveryService = discoveryService;

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
                processCreateAPIKey(entity);
                break;
            case UPDATE:
                processUpdateAPIKey(entity, context.getVertex(entity.getGuid()));
                break;
            default:
                throw new AtlasBaseException(BAD_REQUEST, "Invalid Request");
        }
    }

    private void processCreateAPIKey(AtlasEntity APIKey) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder recorder = RequestContext.get().startMetricRecord("processCreateAPIKey");

        try {
            String source = (String) APIKey.getAttribute(ATTR_API_KEY_SOURCE);
            String category = (String) APIKey.getAttribute(ATTR_API_KEY_CATEGORY);

            APIKey.setAttribute(QUALIFIED_NAME, getUUID());

            if (isInternal(source, category)) {

                APIKeyResponse response = createKeycloakAndLadonPolicies(APIKey);
                String tokenUserName = response.getAttributes().getServiceUsername();

                APIKey.setAttribute(ATTR_API_KEY_SERVICE_USER_NAME, tokenUserName);
                APIKey.setAttribute(ATTR_API_KEY_TOKEN_LIFE, response.getAttributes().getLifespan());

                if (StringUtils.isEmpty(tokenUserName)) {
                    throw new AtlasBaseException(BAD_REQUEST, ATTR_API_KEY_SERVICE_USER_NAME + " for token must be specified");
                }

                List<AtlasEntity> policies = getPoliciesForPermissions(response.getAttributes().getWorkspacePermissionsList());

                if (CollectionUtils.isNotEmpty(policies)) {
                    for (AtlasEntity policy : policies) {
                        List<String> users = AccessControlUtils.getPolicyUsers(policy);
                        users.add(tokenUserName);
                        policy.setAttribute(ATTR_POLICY_USERS, users);
                    }

                    AtlasEntityStream stream = new AtlasEntityStream(policies);
                    entityStore.createOrUpdate(stream, false);
                }

                if (CollectionUtils.isNotEmpty(personaQNames)) {
                    List<String> userList = Arrays.asList(tokenUserName);

                    for (String qualifiedName : personaQNames) {
                        String role = AccessControlUtils.getPersonaRoleName(qualifiedName);

                        keycloakStore.updateRoleAddUsers(role, userList);
                    }
                }
            }
        } finally {
            RequestContext.get().endMetricRecord(recorder);
        }
    }

    private List<AtlasEntity> getPoliciesForPermissions(List<String> permissions) throws AtlasBaseException {
        List<AtlasEntity> ret = new ArrayList<>();
        List<List<String>> chunkedPermissions = ListUtils.partition(permissions, 50);

        IndexSearchParams indexSearchParams = new IndexSearchParams();
        for (List<String> chunk : chunkedPermissions) {
            Map<String, Object> dsl = new HashMap<>();
            dsl.put("size", "50");
            indexSearchParams.setAttributes(new HashSet<String>() {{ add(ATTR_POLICY_USERS); }} );

            List mustClauseList = new ArrayList();
            mustClauseList.add(mapOf("term", mapOf("__typeName.keyword", POLICY_ENTITY_TYPE)));
            mustClauseList.add(mapOf("term", mapOf("__state", "ACTIVE")));

            List shouldClauseList = new ArrayList();
            for (String permission : chunk) {
                shouldClauseList.add(mapOf("term", mapOf("qualifiedName", permission)));
            }
            mustClauseList.add(mapOf("bool", mapOf("should", shouldClauseList)));

            dsl.put("query", mapOf("bool", mapOf("must", mustClauseList)));
            indexSearchParams.setDsl(dsl);

            AtlasSearchResult result = discoveryService.directIndexSearch(indexSearchParams);
            if (result != null && CollectionUtils.isNotEmpty(result.getEntities())) {
                for (AtlasEntityHeader header : result.getEntities()) {
                    AtlasEntity entity = new AtlasEntity();

                    entity.setTypeName(header.getTypeName());
                    entity.setAttributes(header.getAttributes());
                    entity.setGuid(header.getGuid());
                    entity.setStatus(header.getStatus());
                    entity.setCreateTime(header.getCreateTime());
                    entity.setCreatedBy(header.getCreatedBy());
                    entity.setUpdateTime(header.getUpdateTime());
                    entity.setUpdatedBy(header.getUpdatedBy());
                    entity.setDeleteHandler(header.getDeleteHandler());

                    ret.add(entity);
                }
            }
        }

        return ret;
    }

    private APIKeyResponse createKeycloakAndLadonPolicies(AtlasEntity apiKey) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder recorder = RequestContext.get().startMetricRecord("createKeycloakAndLadonPolicies");
        APIKeyResponse ret = null;

        try {
            APIKeyRequest request = new APIKeyRequest();

            request.setDisplayName((String) apiKey.getAttribute(NAME));
            request.setDescription((String) apiKey.getAttribute(DESCRIPTION));

            if (apiKey.hasAttribute(ATTR_API_KEY_TOKEN_LIFE)) {
                request.setValiditySeconds((Long) apiKey.getAttribute(ATTR_API_KEY_TOKEN_LIFE));
            }

            if (apiKey.hasRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS)) {
                List<AtlasRelatedObjectId> personas = getActivePersonaObjectIds(apiKey);

                for (AtlasObjectId objectId : personas) {
                    personaQNames.add(getObjectIdQualifiedName(objectId));
                }

                //TODO: enable once Heracles Bad request issue is resolved
                //request.setPersonas(personaQNames);
            }

            ret = heraclesService.createAPIToken(request);
        } finally {
            RequestContext.get().endMetricRecord(recorder);
        }

        return ret;
    }

    private APIKeyResponse removeKeycloakAndLadonPolicies(AtlasEntity apiKey) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder recorder = RequestContext.get().startMetricRecord("removeKeycloakAndLadonPolicies");
        APIKeyResponse ret = null;

        try {
            APIKeyRequest request = new APIKeyRequest();

            request.setDisplayName((String) apiKey.getAttribute(NAME));
            request.setDescription((String) apiKey.getAttribute(DESCRIPTION));

            if (apiKey.hasAttribute(ATTR_API_KEY_TOKEN_LIFE)) {
                request.setValiditySeconds((Long) apiKey.getAttribute(ATTR_API_KEY_TOKEN_LIFE));
            }

            if (apiKey.hasRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS)) {
                List<AtlasRelatedObjectId> personas = getActivePersonaObjectIds(apiKey);

                for (AtlasObjectId objectId : personas) {
                    personaQNames.add(getObjectIdQualifiedName(objectId));
                }

                //TODO: enable once Heracles Bad request issue is resolved
                //request.setPersonas(personaQNames);
            }

            ret = heraclesService.createAPIToken(request);
        } finally {
            RequestContext.get().endMetricRecord(recorder);
        }

        return ret;
    }

    private List<AtlasRelatedObjectId> getActivePersonaObjectIds(AtlasEntity apiKey) {
        List<AtlasRelatedObjectId> ret = new ArrayList<>(0);

        if (apiKey.hasAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS)) {
            ret = (List<AtlasRelatedObjectId>) apiKey.getRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS);

            ret = ret.stream()
                    .filter(x -> x.getRelationshipStatus().equals(AtlasRelationship.Status.ACTIVE))
                    .collect(Collectors.toList());
        }

        return ret;
    }

    private void processUpdateAPIKey(AtlasEntity APIKey, AtlasVertex existingAPIKey) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder recorder = RequestContext.get().startMetricRecord("createKeycloakAndLadonPolicies");

        try {
            String source = existingAPIKey.getProperty(ATTR_API_KEY_SOURCE, String.class);
            String category = existingAPIKey.getProperty(ATTR_API_KEY_CATEGORY, String.class);

            if (isInternal(source, category)) {

                AtlasEntity currentEntity = entityRetriever.toAtlasEntity(existingAPIKey);

                if (APIKey.hasAttribute(ATTR_API_KEY_SERVICE_USER_NAME)) {
                    APIKey.setAttribute(ATTR_API_KEY_SERVICE_USER_NAME, currentEntity.getAttribute(ATTR_API_KEY_SERVICE_USER_NAME));
                }

                if (APIKey.hasAttribute(ATTR_API_KEY_CATEGORY)) {
                    APIKey.setAttribute(ATTR_API_KEY_CATEGORY, currentEntity.getAttribute(ATTR_API_KEY_CATEGORY));
                }

                if (APIKey.hasAttribute(ATTR_API_KEY_SOURCE)) {
                    APIKey.setAttribute(ATTR_API_KEY_SOURCE, currentEntity.getAttribute(ATTR_API_KEY_SOURCE));
                }

                if (APIKey.hasAttribute(ATTR_API_KEY_CLIENT_ID)) {
                    APIKey.setAttribute(ATTR_API_KEY_CLIENT_ID, currentEntity.getAttribute(ATTR_API_KEY_CLIENT_ID));
                }

                if (APIKey.hasAttribute(ATTR_API_KEY_TOKEN_LIFE)) {
                    APIKey.setAttribute(ATTR_API_KEY_TOKEN_LIFE, currentEntity.getAttribute(ATTR_API_KEY_TOKEN_LIFE));
                }

                if (APIKey.hasAttribute(ATTR_API_KEY_PERMISSIONS)) {
                    APIKey.setAttribute(ATTR_API_KEY_PERMISSIONS, currentEntity.getAttribute(ATTR_API_KEY_PERMISSIONS));
                }

                if (APIKey.hasRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS)) {

                    List<AtlasRelatedObjectId> newPersonas = (List<AtlasRelatedObjectId>) APIKey.getRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS);
                    List<AtlasRelatedObjectId> currentPersonas = getActivePersonaObjectIds(currentEntity);

                    List<String> newPersonasQnames = new ArrayList<>();
                    List<String> currentPersonasQnames = new ArrayList<>();

                    for (AtlasObjectId newPersona : newPersonas) {
                        newPersonasQnames.add(getObjectIdQualifiedName(newPersona));
                    }

                    for (AtlasObjectId currentPersona : currentPersonas) {
                        currentPersonasQnames.add(getObjectIdQualifiedName(currentPersona));
                    }

                    List<String> personasToAdd = (List<String>) CollectionUtils.removeAll(newPersonasQnames, currentPersonasQnames);
                    List<String> personasToRemove = (List<String>) CollectionUtils.removeAll(currentPersonasQnames, newPersonasQnames);

                    String serviceUserName = (String) currentEntity.getAttribute(ATTR_API_KEY_SERVICE_USER_NAME);
                    List<String> users = Arrays.asList(serviceUserName);

                    if (CollectionUtils.isNotEmpty(personasToAdd)) {
                        for (String personaToAdd : personasToAdd) {
                            String roleName = getPersonaRoleName(personaToAdd);

                            keycloakStore.updateRoleAddUsers(roleName, users);
                        }
                    }

                    if (CollectionUtils.isNotEmpty(personasToRemove)) {
                        for (String personaToRemove : personasToRemove) {
                            String roleName = getPersonaRoleName(personaToRemove);

                            keycloakStore.updateRoleRemoveUsers(roleName, users);
                        }
                    }
                }
            }
        } finally  {
            RequestContext.get().endMetricRecord(recorder);
        }

        APIKey.setAttribute(QUALIFIED_NAME, existingAPIKey.getProperty(QUALIFIED_NAME, String.class));
    }

    private boolean isInternal(String source, String category) {
        return "atlan".equals(source) && "internal".equals(category);
    }

    @Override
    public void processDelete(AtlasVertex vertex) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder recorder = RequestContext.get().startMetricRecord("processDeleteAPIKey");
        AtlasEntity apiKey = entityRetriever.toAtlasEntity(vertex);

        try {
            String source = (String) apiKey.getAttribute(ATTR_API_KEY_SOURCE);
            String category = (String) apiKey.getAttribute(ATTR_API_KEY_CATEGORY);

            if (isInternal(source, category)) {
                List<String> permissions = (List<String>) apiKey.getAttribute(ATTR_API_KEY_PERMISSIONS);
                List<AtlasEntity> policies = getPoliciesForPermissions(permissions);

                String tokenUserName = (String) apiKey.getAttribute(ATTR_API_KEY_SERVICE_USER_NAME);

                if (CollectionUtils.isNotEmpty(policies)) {
                    for (AtlasEntity policy : policies) {
                        List<String> users = AccessControlUtils.getPolicyUsers(policy);
                        users.remove(tokenUserName);
                        policy.setAttribute(ATTR_POLICY_USERS, users);
                    }

                    AtlasEntityStream stream = new AtlasEntityStream(policies);
                    entityStore.createOrUpdate(stream, false);
                }

                if (apiKey.hasRelationshipAttribute(REL_ATTR_API_KEY_ACCESS_PERSONAS)) {
                    List<AtlasRelatedObjectId> personas = getActivePersonaObjectIds(apiKey);

                    for (AtlasObjectId objectId : personas) {
                        personaQNames.add(getObjectIdQualifiedName(objectId));
                    }

                    //TODO: enable once Heracles Bad request issue is resolved
                    //request.setPersonas(personaQNames);
                }
            }
        } finally {
            RequestContext.get().endMetricRecord(recorder);
        }
    }

    private String getObjectIdQualifiedName(AtlasObjectId objectId) throws AtlasBaseException {
        String ret;

        if (MapUtils.isNotEmpty(objectId.getUniqueAttributes()) &&
                StringUtils.isNotEmpty((String) objectId.getUniqueAttributes().get(QUALIFIED_NAME))) {
            String qName = (String) objectId.getUniqueAttributes().get(QUALIFIED_NAME);
            ret = qName;

        } else {

            AtlasVertex personaVertex = entityRetriever.getEntityVertex(objectId.getGuid());
            String qName = personaVertex.getProperty(QUALIFIED_NAME, String.class);
            ret = qName;
        }

        return ret;
    }
}