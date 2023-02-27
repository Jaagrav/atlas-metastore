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
package org.apache.atlas.aliasstore;

import org.apache.atlas.ESAliasRequestBuilder;
import org.apache.atlas.ESAliasRequestBuilder.AliasAction;
import org.apache.atlas.RequestContext;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasObjectId;
import org.apache.atlas.model.instance.AtlasStruct;
import org.apache.atlas.repository.graphdb.AtlasGraph;
import org.apache.atlas.repository.store.graph.v2.EntityGraphRetriever;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.hbase.security.access.AccessControlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.atlas.ESAliasRequestBuilder.ESAliasAction.ADD;
import static org.apache.atlas.repository.Constants.CONNECTION_ENTITY_TYPE;
import static org.apache.atlas.repository.Constants.PERSONA_ENTITY_TYPE;
import static org.apache.atlas.repository.Constants.PROPAGATED_TRAIT_NAMES_PROPERTY_KEY;
import static org.apache.atlas.repository.Constants.QUALIFIED_NAME;
import static org.apache.atlas.repository.Constants.TRAIT_NAMES_PROPERTY_KEY;
import static org.apache.atlas.repository.Constants.VERTEX_INDEX_NAME;
import static org.apache.atlas.repository.util.AccessControlUtils.ACCESS_READ_PERSONA_METADATA;
import static org.apache.atlas.repository.util.AccessControlUtils.ACCESS_READ_PURPOSE_GLOSSARY;
import static org.apache.atlas.repository.util.AccessControlUtils.ACCESS_READ_PURPOSE_METADATA;
import static org.apache.atlas.repository.util.AccessControlUtils.getConnectionQualifiedNameFromPolicyAssets;
import static org.apache.atlas.repository.util.AccessControlUtils.getESAliasName;
import static org.apache.atlas.repository.util.AccessControlUtils.getIsAllow;
import static org.apache.atlas.repository.util.AccessControlUtils.getPolicies;
import static org.apache.atlas.repository.util.AccessControlUtils.getPolicyActions;
import static org.apache.atlas.repository.util.AccessControlUtils.getPolicyAssets;
import static org.apache.atlas.repository.util.AccessControlUtils.getPurposeTags;
import static org.apache.atlas.repository.util.AccessControlUtils.mapOf;


@Component
public class ESAliasStore implements IndexAliasStore {
    private static final Logger LOG = LoggerFactory.getLogger(ESAliasStore.class);

    private final AtlasGraph graph;
    private final EntityGraphRetriever entityRetriever;

    @Inject
    public ESAliasStore(AtlasGraph graph,
                        EntityGraphRetriever entityRetriever) {
        this.graph = graph;
        this.entityRetriever = entityRetriever;
    }

    @Override
    public boolean createAlias(AtlasEntity entity) throws AtlasBaseException {
        String aliasName = getAliasName(entity);

        ESAliasRequestBuilder requestBuilder = new ESAliasRequestBuilder();
        requestBuilder.addAction(ADD, new AliasAction(VERTEX_INDEX_NAME, aliasName));

        graph.createOrUpdateESAlias(requestBuilder);
        return true;
    }

    @Override
    public boolean updateAlias(AtlasEntity policy, AtlasEntity.AtlasEntityWithExtInfo accessControl) throws AtlasBaseException {
        String aliasName = getAliasName(policy);

        Map<String, Object> filter;

        if (PERSONA_ENTITY_TYPE.equals(accessControl.getEntity().getTypeName())) {
            filter = getFilterForPersona(policy, accessControl);
        } else {
            filter = getFilterForPurpose(policy, accessControl);
        }

        ESAliasRequestBuilder requestBuilder = new ESAliasRequestBuilder();
        requestBuilder.addAction(ADD, new AliasAction(VERTEX_INDEX_NAME, aliasName, filter));

        graph.createOrUpdateESAlias(requestBuilder);

        return true;
    }

    @Override
    public boolean deleteAlias(String aliasName) throws AtlasBaseException {
        graph.deleteESAlias(VERTEX_INDEX_NAME, aliasName);
        return true;
    }

    private Map<String, Object> getFilterForPersona(AtlasEntity policy, AtlasEntity.AtlasEntityWithExtInfo persona) throws AtlasBaseException {
        List<Map<String, Object>> allowClauseList = new ArrayList<>();
        List<Map<String, Object>> denyClauseList = new ArrayList<>();

        List<AtlasEntity> policies = getPolicies(persona);
        if (CollectionUtils.isNotEmpty(policies)) {
            personaPolicyToESDslClauses(policies, allowClauseList, denyClauseList);
        }

        return esClausesToFilter(allowClauseList, denyClauseList);
    }

    private Map<String, Object> getFilterForPurpose(AtlasEntity policy, AtlasEntity.AtlasEntityWithExtInfo purpose) throws AtlasBaseException {

        List<Map<String, Object>> allowClauseList = new ArrayList<>();
        List<Map<String, Object>> denyClauseList = new ArrayList<>();

        List<AtlasEntity> policies = getPolicies(purpose);
        List<String> tags = getPurposeTags(purpose.getEntity());

        if (CollectionUtils.isNotEmpty(policies)) {

            for (AtlasEntity entity: policies) {
                if (RequestContext.get().isDeletedEntity(policy.getGuid())) {
                    continue;
                }

                if (getPolicyActions(entity).contains(ACCESS_READ_PURPOSE_METADATA)) {
                    boolean allow = getIsAllow(entity);

                    addPurposeMetadataFilterClauses(tags, allow ? allowClauseList : denyClauseList);
                }
            }
        }

        return esClausesToFilter(allowClauseList, denyClauseList);
    }

    private void personaPolicyToESDslClauses(List<AtlasEntity> policies,
                                             List<Map<String, Object>> allowClauseList,
                                             List<Map<String, Object>> denyClauseList) throws AtlasBaseException {
        for (AtlasEntity policy: policies) {

            if (RequestContext.get().isDeletedEntity(policy.getGuid())) {
                continue;
            }

            List<Map<String, Object>> clauseList = getIsAllow(policy) ? allowClauseList : denyClauseList;
            List<String> assets = getPolicyAssets(policy);

            if (getPolicyActions(policy).contains(ACCESS_READ_PERSONA_METADATA)) {
                boolean addConnectionFilter = true;
                String connectionQName = getConnectionQualifiedNameFromPolicyAssets(entityRetriever, assets);

                for (String asset : assets) {
                    if (StringUtils.equals(connectionQName, asset)) {
                        addConnectionFilter = false;
                    }

                    addPersonaMetadataFilterClauses(asset, clauseList);
                }

                if (addConnectionFilter) {
                    addPersonaMetadataFilterConnectionClause(connectionQName, clauseList);
                }
            } else if (getPolicyActions(policy).contains(ACCESS_READ_PURPOSE_GLOSSARY)) {
                for (String glossaryQName : assets) {
                    addPersonaMetadataFilterClauses(glossaryQName, clauseList);
                }
            }
        }
    }

    private Map<String, Object> esClausesToFilter(List<Map<String, Object>> allowClauseList, List<Map<String, Object>> denyClauseList) {
        Map<String, Object> eSFilterBoolClause = new HashMap<>();
        if (CollectionUtils.isNotEmpty(allowClauseList)) {
            eSFilterBoolClause.put("should", allowClauseList);
        }

        if (CollectionUtils.isNotEmpty(denyClauseList)) {
            eSFilterBoolClause.put("must_not", denyClauseList);
        }

        return mapOf("bool", eSFilterBoolClause);
    }

    private String getAliasName(AtlasEntity entity) {
        return getESAliasName(entity);
    }

    private void addPersonaMetadataFilterClauses(String asset, List<Map<String, Object>> clauseList) {
        addPersonaFilterClauses(asset, clauseList);
    }

    private void addPersonaMetadataFilterConnectionClause(String connection, List<Map<String, Object>> clauseList) {
        clauseList.add(mapOf("term", mapOf(QUALIFIED_NAME, connection)));
    }

    private void addPersonaFilterClauses(String asset, List<Map<String, Object>> clauseList) {
        clauseList.add(mapOf("term", mapOf(QUALIFIED_NAME, asset)));
        clauseList.add(mapOf("wildcard", mapOf(QUALIFIED_NAME, asset + "/*")));
        clauseList.add(mapOf("wildcard", mapOf(QUALIFIED_NAME, "*@" + asset)));
    }

    private void addPurposeMetadataFilterClauses(List<String> tags, List<Map<String, Object>> clauseList) {
        clauseList.add(mapOf("terms", mapOf(TRAIT_NAMES_PROPERTY_KEY, tags)));
        clauseList.add(mapOf("terms", mapOf(PROPAGATED_TRAIT_NAMES_PROPERTY_KEY, tags)));
    }
}
