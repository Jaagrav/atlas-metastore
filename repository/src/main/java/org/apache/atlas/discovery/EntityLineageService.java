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

package org.apache.atlas.discovery;


import com.google.common.annotations.VisibleForTesting;
import org.apache.atlas.AtlasConfiguration;
import org.apache.atlas.AtlasErrorCode;
import org.apache.atlas.GraphTransactionInterceptor;
import org.apache.atlas.RequestContext;
import org.apache.atlas.annotation.GraphTransaction;
import org.apache.atlas.authorize.AtlasAuthorizationUtils;
import org.apache.atlas.authorize.AtlasEntityAccessRequest;
import org.apache.atlas.authorize.AtlasPrivilege;
import org.apache.atlas.authorize.AtlasSearchResultScrubRequest;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.model.discovery.AtlasSearchResult;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasEntity.AtlasEntityWithExtInfo;
import org.apache.atlas.model.instance.AtlasEntityHeader;
import org.apache.atlas.model.instance.AtlasObjectId;
import org.apache.atlas.model.lineage.AtlasLineageInfo;
import org.apache.atlas.model.lineage.AtlasLineageInfo.LineageDirection;
import org.apache.atlas.model.lineage.AtlasLineageInfo.LineageRelation;
import org.apache.atlas.model.lineage.AtlasLineageRequest;
import org.apache.atlas.model.lineage.LineageChildrenInfo;
import org.apache.atlas.repository.Constants;
import org.apache.atlas.repository.graphdb.AtlasEdge;
import org.apache.atlas.repository.graphdb.AtlasGraph;
import org.apache.atlas.repository.graphdb.AtlasVertex;
import org.apache.atlas.repository.store.graph.v2.AtlasGraphUtilsV2;
import org.apache.atlas.repository.store.graph.v2.EntityGraphRetriever;
import org.apache.atlas.type.AtlasEntityType;
import org.apache.atlas.type.AtlasTypeRegistry;
import org.apache.atlas.type.AtlasTypeUtil;
import org.apache.atlas.util.AtlasGremlinQueryProvider;
import org.apache.atlas.utils.AtlasPerfMetrics;
import org.apache.atlas.v1.model.lineage.SchemaResponse.SchemaDetails;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.inject.Inject;
import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.util.*;
import java.util.stream.Collectors;

import static org.apache.atlas.AtlasClient.DATA_SET_SUPER_TYPE;
import static org.apache.atlas.AtlasClient.PROCESS_SUPER_TYPE;
import static org.apache.atlas.AtlasErrorCode.INSTANCE_LINEAGE_QUERY_FAILED;
import static org.apache.atlas.model.instance.AtlasEntity.Status.DELETED;
import static org.apache.atlas.model.lineage.AtlasLineageInfo.LineageDirection.*;
import static org.apache.atlas.repository.Constants.ACTIVE_STATE_VALUE;
import static org.apache.atlas.repository.Constants.RELATIONSHIP_GUID_PROPERTY_KEY;
import static org.apache.atlas.repository.graph.GraphHelper.*;
import static org.apache.atlas.repository.graphdb.AtlasEdgeDirection.IN;
import static org.apache.atlas.repository.graphdb.AtlasEdgeDirection.OUT;
import static org.apache.atlas.util.AtlasGremlinQueryProvider.AtlasGremlinQuery.*;

@Service
public class EntityLineageService implements AtlasLineageService {
    private static final Logger LOG = LoggerFactory.getLogger(EntityLineageService.class);

    private static final String PROCESS_INPUTS_EDGE = "__Process.inputs";
    private static final String PROCESS_OUTPUTS_EDGE = "__Process.outputs";
    private static final String COLUMNS = "columns";
    private static final boolean LINEAGE_USING_GREMLIN = AtlasConfiguration.LINEAGE_USING_GREMLIN.getBoolean();

    private final AtlasGraph graph;
    private final AtlasGremlinQueryProvider gremlinQueryProvider;
    private final EntityGraphRetriever entityRetriever;
    private final AtlasTypeRegistry atlasTypeRegistry;
    private final VertexEdgeCache vertexEdgeCache;

    @Inject
    EntityLineageService(AtlasTypeRegistry typeRegistry, AtlasGraph atlasGraph, VertexEdgeCache vertexEdgeCache) {
        this.graph = atlasGraph;
        this.gremlinQueryProvider = AtlasGremlinQueryProvider.INSTANCE;
        this.entityRetriever = new EntityGraphRetriever(atlasGraph, typeRegistry);
        this.atlasTypeRegistry = typeRegistry;
        this.vertexEdgeCache = vertexEdgeCache;
    }

    @VisibleForTesting
    EntityLineageService() {
        this.graph = null;
        this.gremlinQueryProvider = null;
        this.entityRetriever = null;
        this.atlasTypeRegistry = null;
        this.vertexEdgeCache = null;
    }

    @Override
    public AtlasLineageInfo getAtlasLineageInfo(String guid, LineageDirection direction, int depth, boolean hideProcess, int offset, int limit, boolean calculateRemainingVertexCounts) throws AtlasBaseException {
        return getAtlasLineageInfo(new AtlasLineageRequest(guid, depth, direction, hideProcess, offset, limit, calculateRemainingVertexCounts));
    }

    @Override
    @GraphTransaction
    public AtlasLineageInfo getAtlasLineageInfo(AtlasLineageRequest lineageRequest) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metric = RequestContext.get().startMetricRecord("getAtlasLineageInfo");

        AtlasLineageInfo ret;
        String guid = lineageRequest.getGuid();
        AtlasLineageContext lineageRequestContext = new AtlasLineageContext(lineageRequest, atlasTypeRegistry);
        RequestContext.get().setRelationAttrsForSearch(lineageRequest.getRelationAttributes());

        AtlasEntityHeader entity = entityRetriever.toAtlasEntityHeaderWithClassifications(guid);

        AtlasEntityType entityType = atlasTypeRegistry.getEntityTypeByName(entity.getTypeName());

        if (entityType == null) {
            throw new AtlasBaseException(AtlasErrorCode.TYPE_NAME_NOT_FOUND, entity.getTypeName());
        }

        boolean isDataSet = entityType.getTypeAndAllSuperTypes().contains(DATA_SET_SUPER_TYPE);

        if (!isDataSet) {
            boolean isProcess = entityType.getTypeAndAllSuperTypes().contains(PROCESS_SUPER_TYPE);

            if (!isProcess) {
                throw new AtlasBaseException(AtlasErrorCode.INVALID_LINEAGE_ENTITY_TYPE, guid, entity.getTypeName());
            } else if (lineageRequest.isHideProcess()) {
                throw new AtlasBaseException(AtlasErrorCode.INVALID_LINEAGE_ENTITY_TYPE_HIDE_PROCESS, guid, entity.getTypeName());
            }
            lineageRequestContext.setProcess(isProcess);
        }
        lineageRequestContext.setDataset(isDataSet);


        if (LINEAGE_USING_GREMLIN) {
            ret = getLineageInfoV1(lineageRequestContext);
        } else {
            ret = getLineageInfoV2(lineageRequestContext);
        }

        scrubLineageEntities(ret.getGuidEntityMap().values());
        RequestContext.get().endMetricRecord(metric);
        return ret;
    }

    @Override
    @GraphTransaction
    public AtlasLineageInfo getAtlasLineageInfo(String guid, LineageDirection direction, int depth) throws AtlasBaseException {
        return getAtlasLineageInfo(guid, direction, depth, false, -1, -1, false);
    }

    @Override
    @GraphTransaction
    public SchemaDetails getSchemaForHiveTableByName(final String datasetName) throws AtlasBaseException {
        if (StringUtils.isEmpty(datasetName)) {
            // TODO: Complete error handling here
            throw new AtlasBaseException(AtlasErrorCode.BAD_REQUEST);
        }

        AtlasEntityType hive_table = atlasTypeRegistry.getEntityTypeByName("hive_table");

        Map<String, Object> lookupAttributes = new HashMap<>();
        lookupAttributes.put("qualifiedName", datasetName);
        String guid = AtlasGraphUtilsV2.getGuidByUniqueAttributes(hive_table, lookupAttributes);

        return getSchemaForHiveTableByGuid(guid);
    }

    @Override
    @GraphTransaction
    public SchemaDetails getSchemaForHiveTableByGuid(final String guid) throws AtlasBaseException {
        if (StringUtils.isEmpty(guid)) {
            throw new AtlasBaseException(AtlasErrorCode.BAD_REQUEST);
        }
        SchemaDetails ret = new SchemaDetails();
        AtlasEntityType hive_column = atlasTypeRegistry.getEntityTypeByName("hive_column");

        ret.setDataType(AtlasTypeUtil.toClassTypeDefinition(hive_column));

        AtlasEntityWithExtInfo entityWithExtInfo = entityRetriever.toAtlasEntityWithExtInfo(guid);
        AtlasEntity entity = entityWithExtInfo.getEntity();

        AtlasAuthorizationUtils.verifyAccess(new AtlasEntityAccessRequest(atlasTypeRegistry, AtlasPrivilege.ENTITY_READ, new AtlasEntityHeader(entity)),
                "read entity schema: guid=", guid);

        Map<String, AtlasEntity> referredEntities = entityWithExtInfo.getReferredEntities();
        List<String> columnIds = getColumnIds(entity);

        if (MapUtils.isNotEmpty(referredEntities)) {
            List<Map<String, Object>> rows = referredEntities.entrySet()
                    .stream()
                    .filter(e -> isColumn(columnIds, e))
                    .map(e -> AtlasTypeUtil.toMap(e.getValue()))
                    .collect(Collectors.toList());
            ret.setRows(rows);
        }

        return ret;
    }

    private void scrubLineageEntities(Collection<AtlasEntityHeader> entityHeaders) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("scrubLineageEntities");

        AtlasSearchResult searchResult = new AtlasSearchResult();
        searchResult.setEntities(new ArrayList<>(entityHeaders));
        AtlasSearchResultScrubRequest request = new AtlasSearchResultScrubRequest(atlasTypeRegistry, searchResult);

        AtlasAuthorizationUtils.scrubSearchResults(request, true);
        RequestContext.get().endMetricRecord(metricRecorder);
    }

    private List<String> getColumnIds(AtlasEntity entity) {
        List<String> ret = new ArrayList<>();
        Object columnObjs = entity.getAttribute(COLUMNS);

        if (columnObjs instanceof List) {
            for (Object pkObj : (List) columnObjs) {
                if (pkObj instanceof AtlasObjectId) {
                    ret.add(((AtlasObjectId) pkObj).getGuid());
                }
            }
        }

        return ret;
    }

    private boolean isColumn(List<String> columnIds, Map.Entry<String, AtlasEntity> e) {
        return columnIds.contains(e.getValue().getGuid());
    }

    private AtlasLineageInfo getLineageInfoV1(AtlasLineageContext lineageContext) throws AtlasBaseException {
        AtlasLineageInfo ret;
        LineageDirection direction = lineageContext.getDirection();

        if (direction.equals(INPUT)) {
            ret = getLineageInfo(lineageContext, INPUT);
        } else if (direction.equals(OUTPUT)) {
            ret = getLineageInfo(lineageContext, OUTPUT);
        } else {
            ret = getBothLineageInfoV1(lineageContext);
        }

        return ret;
    }

    private AtlasLineageInfo getLineageInfo(AtlasLineageContext lineageContext, LineageDirection direction) throws AtlasBaseException {
        int depth = lineageContext.getDepth();
        String guid = lineageContext.getGuid();
        boolean isDataSet = lineageContext.isDataset();

        final Map<String, Object> bindings = new HashMap<>();
        String lineageQuery = getLineageQuery(guid, direction, depth, isDataSet, bindings);
        List results = executeGremlinScript(bindings, lineageQuery);
        Map<String, AtlasEntityHeader> entities = new HashMap<>();
        Set<LineageRelation> relations = new HashSet<>();

        if (CollectionUtils.isNotEmpty(results)) {
            for (Object result : results) {
                if (result instanceof Map) {
                    for (final Object o : ((Map) result).entrySet()) {
                        final Map.Entry entry = (Map.Entry) o;
                        Object value = entry.getValue();

                        if (value instanceof List) {
                            for (Object elem : (List) value) {
                                if (elem instanceof AtlasEdge) {
                                    processEdge((AtlasEdge) elem, entities, relations, lineageContext);
                                } else {
                                    LOG.warn("Invalid value of type {} found, ignoring", (elem != null ? elem.getClass().getSimpleName() : "null"));
                                }
                            }
                        } else if (value instanceof AtlasEdge) {
                            processEdge((AtlasEdge) value, entities, relations, lineageContext);
                        } else {
                            LOG.warn("Invalid value of type {} found, ignoring", (value != null ? value.getClass().getSimpleName() : "null"));
                        }
                    }
                } else if (result instanceof AtlasEdge) {
                    processEdge((AtlasEdge) result, entities, relations, lineageContext);
                }
            }
        }

        return new AtlasLineageInfo(guid, entities, relations, direction, depth, -1, -1);
    }

    private AtlasLineageInfo getLineageInfoV2(AtlasLineageContext lineageContext) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metric = RequestContext.get().startMetricRecord("getLineageInfoV2");

        int depth = lineageContext.getDepth();
        String guid = lineageContext.getGuid();
        LineageDirection direction = lineageContext.getDirection();

        AtlasLineageInfo ret = initializeLineageInfo(guid, direction, depth, lineageContext.getLimit(), lineageContext.getOffset());

        if (depth == 0) {
            depth = -1;
        }

        if (lineageContext.isDataset()) {
            AtlasVertex datasetVertex = AtlasGraphUtilsV2.findByGuid(this.graph, guid);
            lineageContext.setStartDatasetVertex(datasetVertex);

            if (direction == INPUT || direction == BOTH) {
                traverseEdges(datasetVertex, true, depth, new HashSet<>(), ret, lineageContext);
            }

            if (direction == OUTPUT || direction == BOTH) {
                traverseEdges(datasetVertex, false, depth, new HashSet<>(), ret, lineageContext);
            }
        } else {
            AtlasVertex processVertex = AtlasGraphUtilsV2.findByGuid(this.graph, guid);

            // make one hop to the next dataset vertices from process vertex and traverse with 'depth = depth - 1'
            if (direction == INPUT || direction == BOTH) {
                Iterator<AtlasEdge> processEdges = vertexEdgeCache.getEdges(processVertex, OUT, PROCESS_INPUTS_EDGE).iterator();

                List<AtlasEdge> qualifyingEdges = getQualifyingProcessEdges(processEdges, lineageContext);
                ret.setHasChildrenForDirection(getGuid(processVertex), new LineageChildrenInfo(INPUT, hasMoreChildren(qualifyingEdges)));

                for (AtlasEdge processEdge : qualifyingEdges) {
                    addEdgeToResult(processEdge, ret, lineageContext);

                    AtlasVertex datasetVertex = processEdge.getInVertex();

                    traverseEdges(datasetVertex, true, depth - 1, new HashSet<>(), ret, lineageContext);
                }
            }

            if (direction == OUTPUT || direction == BOTH) {
                Iterator<AtlasEdge> processEdges = vertexEdgeCache.getEdges(processVertex, OUT, PROCESS_OUTPUTS_EDGE).iterator();

                List<AtlasEdge> qualifyingEdges = getQualifyingProcessEdges(processEdges, lineageContext);
                ret.setHasChildrenForDirection(getGuid(processVertex), new LineageChildrenInfo(OUTPUT, hasMoreChildren(qualifyingEdges)));

                for (AtlasEdge processEdge : qualifyingEdges) {
                    addEdgeToResult(processEdge, ret, lineageContext);

                    AtlasVertex datasetVertex = processEdge.getInVertex();

                    traverseEdges(datasetVertex, false, depth - 1, new HashSet<>(), ret, lineageContext);
                }
            }
        }
        RequestContext.get().endMetricRecord(metric);

        return ret;
    }

    private List<AtlasEdge> getQualifyingProcessEdges(Iterator<AtlasEdge> processEdges, AtlasLineageContext lineageContext) {
        AtlasPerfMetrics.MetricRecorder metric = RequestContext.get().startMetricRecord("getQualifyingProcessEdges");
        List<AtlasEdge> qualifyingEdges = new ArrayList<>();
        while (processEdges.hasNext()) {
            AtlasEdge processEdge = processEdges.next();
            if (shouldProcessEdge(lineageContext, processEdge) && lineageContext.evaluate(processEdge.getInVertex())) {
                qualifyingEdges.add(processEdge);
            }
        }
        RequestContext.get().endMetricRecord(metric);
        return qualifyingEdges;
    }

    private void addEdgeToResult(AtlasEdge edge, AtlasLineageInfo lineageInfo,
                                 AtlasLineageContext requestContext) throws AtlasBaseException {
        if (!lineageContainsEdge(lineageInfo, edge)) {
            processEdge(edge, lineageInfo, requestContext);
        }
    }

    private boolean hasMoreChildren(List<AtlasEdge> edges) {
        return edges.stream().anyMatch(edge -> getStatus(edge) == AtlasEntity.Status.ACTIVE);
    }

    private void traverseEdges(AtlasVertex currentVertex, boolean isInput, int depth, Set<String> visitedVertices, AtlasLineageInfo ret,
                               AtlasLineageContext lineageContext) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metric = RequestContext.get().startMetricRecord("traverseEdges");
        if (depth != 0) {
            processIntermediateLevel(currentVertex, isInput, depth, visitedVertices, ret, lineageContext);
        } else {
            processLastLevel(currentVertex, isInput, ret, lineageContext);
        }
        RequestContext.get().endMetricRecord(metric);
    }

    private void processIntermediateLevel(AtlasVertex currentVertex,
                                          boolean isInput,
                                          int depth,
                                          Set<String> visitedVertices,
                                          AtlasLineageInfo ret,
                                          AtlasLineageContext lineageContext) throws AtlasBaseException {
        // keep track of visited vertices to avoid circular loop
        visitedVertices.add(currentVertex.getIdForDisplay());

        if (!vertexMatchesEvaluation(currentVertex, lineageContext)) {
            return;
        }
        List<AtlasEdge> currentVertexEdges = getEdgesOfCurrentVertex(currentVertex, isInput, lineageContext);
        Set<String> paginationCalculatedVertices = new HashSet<>();
        paginationCalculatedVertices.add(currentVertex.getIdForDisplay());
        if (lineageContext.shouldApplyPagination()) {
            if (lineageContext.isCalculateRemainingVertexCounts()) {
                calculateRemainingVertexCounts(currentVertex, isInput, ret);
            }
            addPaginatedVerticesToResult(isInput, depth, visitedVertices, ret, lineageContext, currentVertexEdges, paginationCalculatedVertices);
        } else {
            addLimitlessVerticesToResult(isInput, depth, visitedVertices, ret, lineageContext, currentVertexEdges);
        }
    }

    private void calculateRemainingVertexCounts(AtlasVertex currentVertex, boolean isInput, AtlasLineageInfo ret) {
        if (isInput) {
            Long totalUpstreamVertexCount = getTotalUpstreamVertexCount(getGuid(currentVertex));
            ret.calculateRemainingUpstreamVertexCount(totalUpstreamVertexCount);
        } else {
            Long totalDownstreamVertexCount = getTotalDownstreamVertexCount(getGuid(currentVertex));
            ret.calculateRemainingDownstreamVertexCount(totalDownstreamVertexCount);
        }
    }

    private Long getTotalDownstreamVertexCount(String guid) {
        return (Long) graph
                .V()
                .has("__guid", guid)
                .inE("__Process.inputs").has("__state", "ACTIVE")
                .outV().has("__state", "ACTIVE")
                .outE("__Process.outputs").has("__state", "ACTIVE")
                .inV()
                .count()
                .next();

    }

    private Long getTotalUpstreamVertexCount(String guid) {
        return (Long) graph
                .V()
                .has("__guid", guid)
                .outE("__Process.outputs").has("__state", "ACTIVE")
                .inV().has("__state", "ACTIVE")
                .inE("__Process.inputs").has("__state", "ACTIVE")
                .inV()
                .count()
                .next();
    }

    private void addPaginatedVerticesToResult(boolean isInput,
                                              int depth,
                                              Set<String> visitedVertices,
                                              AtlasLineageInfo ret,
                                              AtlasLineageContext lineageContext,
                                              List<AtlasEdge> currentVertexEdges, Set<String> paginationCalculatedVertices) throws AtlasBaseException {
        long inputVertexCount = !isInput ? nonProcessEntityCount(ret) : 0;
        int currentOffset = lineageContext.getOffset();
        boolean isFirstValidProcessReached = false;
        for (int i = 0; i < currentVertexEdges.size(); i++) {
            AtlasEdge edge = currentVertexEdges.get(i);
            AtlasVertex processVertex = edge.getOutVertex();
            if (!shouldProcessDeletedProcess(lineageContext, processVertex) || getStatus(edge) == DELETED) {
                continue;
            }

            List<AtlasEdge> edgesOfProcess = getEdgesOfProcess(isInput, lineageContext, paginationCalculatedVertices, processVertex);

            if (isFirstValidProcessReached)
                currentOffset = 0;
            if (edgesOfProcess.size() > currentOffset) {
                isFirstValidProcessReached = true;
                ret.setHasChildrenForDirection(getGuid(processVertex), new LineageChildrenInfo(isInput ? INPUT : OUTPUT, hasMoreChildren(edgesOfProcess)));
                boolean isLimitReached = executeCurrentProcessVertex(isInput, depth, visitedVertices, ret, lineageContext, currentVertexEdges, inputVertexCount, currentOffset, i, edge, edgesOfProcess);
                if (isLimitReached)
                    return;
            } else
                currentOffset -= edgesOfProcess.size();
        }
    }

    private List<AtlasEdge> getEdgesOfProcess(boolean isInput, AtlasLineageContext lineageContext, Set<String> paginationCalculatedVertices, AtlasVertex processVertex) {
        List<Pair<AtlasEdge, String>> processEdgeOutputVertexIdPairs = getUnvisitedProcessEdgesWithOutputVertexIds(isInput, lineageContext, paginationCalculatedVertices, processVertex);
        processEdgeOutputVertexIdPairs.forEach(pair -> paginationCalculatedVertices.add(pair.getRight()));
        return processEdgeOutputVertexIdPairs
                .stream()
                .map(Pair::getLeft)
                .collect(Collectors.toList());
    }

    private boolean executeCurrentProcessVertex(boolean isInput,
                                                int depth,
                                                Set<String> visitedVertices,
                                                AtlasLineageInfo ret,
                                                AtlasLineageContext lineageContext,
                                                List<AtlasEdge> currentVertexEdges,
                                                long inputVertexCount, int currentOffset, int vertexEdgeIndex,
                                                AtlasEdge edge,
                                                List<AtlasEdge> edgesOfProcess) throws AtlasBaseException {
        for (int j = currentOffset; j < edgesOfProcess.size(); j++) {
            AtlasEdge edgeOfProcess = edgesOfProcess.get(j);
            AtlasVertex entityVertex = edgeOfProcess.getInVertex();
            if (entityVertex == null) {
                continue;
            }
            if (shouldTerminate(isInput, ret, lineageContext, currentVertexEdges, inputVertexCount, vertexEdgeIndex, edgesOfProcess, j)) {
                return true;
            }
            if (!visitedVertices.contains(entityVertex.getIdForDisplay())) {
                traverseEdges(entityVertex, isInput, depth - 1, visitedVertices, ret, lineageContext);
            }
            if (lineageContext.isHideProcess()) {
                processVirtualEdge(edge, edgeOfProcess, ret, lineageContext);
            } else {
                processEdges(edge, edgeOfProcess, ret, lineageContext);
            }
        }
        return false;
    }

    private boolean shouldProcessDeletedProcess(AtlasLineageContext lineageContext, AtlasVertex processVertex) {
        return isVertexActive(processVertex) || lineageContext.isAllowDeletedProcess();
    }

    private boolean isVertexActive(AtlasVertex vertex) {
        return getStatus(vertex) == AtlasEntity.Status.ACTIVE;
    }

    private List<Pair<AtlasEdge, String>> getUnvisitedProcessEdgesWithOutputVertexIds(boolean isInput, AtlasLineageContext lineageContext, Set<String> paginationCalculatedVertices, AtlasVertex processVertex) {
        return getEdgesOfProcess(isInput, lineageContext, processVertex)
                .stream()
                .map(processEdge -> Pair.of(processEdge, processEdge.getInVertex()))
                .filter(pair -> pair.getRight() != null)
                .map(pair -> Pair.of(pair.getLeft(), pair.getRight().getIdForDisplay()))
                .filter(pair -> !paginationCalculatedVertices.contains(pair.getRight()))
                .collect(Collectors.toList());
    }

    @VisibleForTesting
    boolean shouldTerminate(boolean isInput,
                            AtlasLineageInfo ret,
                            AtlasLineageContext lineageContext,
                            List<AtlasEdge> currentVertexEdges,
                            long inputVertexCount,
                            int currentVertexEdgeIndex,
                            List<AtlasEdge> edgesOfProcess,
                            int processEdgeIndex) {
        if (lineageContext.getDirection() == BOTH) {
            if (isInput && nonProcessEntityCount(ret) == lineageContext.getLimit()) {
                ret.setHasMoreUpstreamVertices(true);
                return true;
            } else if (!isInput && nonProcessEntityCount(ret) - inputVertexCount == lineageContext.getLimit()) {
                ret.setHasMoreDownstreamVertices(true);
                return true;
            }
        } else if (nonProcessEntityCount(ret) == lineageContext.getLimit()) {
            setVertexCountsForOneDirection(isInput, ret, currentVertexEdges, currentVertexEdgeIndex, edgesOfProcess, processEdgeIndex);
            return true;
        }
        return false;
    }

    private void setVertexCountsForOneDirection(boolean isInput, AtlasLineageInfo ret, List<AtlasEdge> currentVertexEdges, int currentVertexEdgeIndex, List<AtlasEdge> edgesOfProcess, int processEdgeIndex) {
        if (isInput) {
            ret.setHasMoreUpstreamVertices(true);
        } else {
            ret.setHasMoreDownstreamVertices(true);
        }
    }

    private long nonProcessEntityCount(AtlasLineageInfo ret) {
        long nonProcessVertexCount = ret.getGuidEntityMap()
                .values()
                .stream()
                .filter(vertex -> !vertex.getTypeName().contains("Process"))
                .count();

        //We subtract 1 because the base entity is added to the result as well. We want 'limit' number of child
        //vertices, excluding the base entity.
        return Math.max(nonProcessVertexCount - 1, 0);
    }

    private void addLimitlessVerticesToResult(boolean isInput, int depth, Set<String> visitedVertices, AtlasLineageInfo ret, AtlasLineageContext lineageContext, List<AtlasEdge> currentVertexEdges) throws AtlasBaseException {
        for (AtlasEdge edge : currentVertexEdges) {
            AtlasVertex processVertex = edge.getOutVertex();
            List<AtlasEdge> outputEdgesOfProcess = getEdgesOfProcess(isInput, lineageContext, processVertex);

            ret.setHasChildrenForDirection(getGuid(processVertex), new LineageChildrenInfo(isInput ? INPUT : OUTPUT, hasMoreChildren(outputEdgesOfProcess)));
            for (AtlasEdge outgoingEdge : outputEdgesOfProcess) {
                AtlasVertex entityVertex = outgoingEdge.getInVertex();

                if (entityVertex != null) {
                    if (lineageContext.isHideProcess()) {
                        processVirtualEdge(edge, outgoingEdge, ret, lineageContext);
                    } else {
                        processEdges(edge, outgoingEdge, ret, lineageContext);
                    }

                    if (!visitedVertices.contains(entityVertex.getIdForDisplay())) {
                        traverseEdges(entityVertex, isInput, depth - 1, visitedVertices, ret, lineageContext);
                    }
                }
            }
        }
    }

    private void processLastLevel(AtlasVertex currentVertex, boolean isInput, AtlasLineageInfo ret, AtlasLineageContext lineageContext) {
        List<AtlasEdge> processEdges = vertexEdgeCache.getEdges(currentVertex, IN, isInput ? PROCESS_OUTPUTS_EDGE : PROCESS_INPUTS_EDGE);
        processEdges = CollectionUtils.isNotEmpty(lineageContext.getIgnoredProcesses()) ? eliminateIgnoredProcesses(processEdges, isInput, lineageContext, currentVertex) : processEdges;
        ret.setHasChildrenForDirection(getGuid(currentVertex), new LineageChildrenInfo(isInput ? INPUT : OUTPUT, hasMoreChildren(processEdges)));
    }

    private List<AtlasEdge> eliminateIgnoredProcesses(List<AtlasEdge> processEdges, boolean isInput, AtlasLineageContext lineageContext, AtlasVertex currentVertex) {
        List<AtlasEdge> edges = new ArrayList<>();
        for (AtlasEdge processEdge : processEdges) {
            AtlasVertex processVertex;
            processVertex = processEdge.getOutVertex();
            if (processVertex != null) {
                if (!childHasSelfCycle(processVertex, currentVertex, isInput) &&
                        !lineageContext.getIgnoredProcesses().contains(processVertex.getProperty(Constants.ENTITY_TYPE_PROPERTY_KEY, String.class))) {
                    edges.add(processEdge);
                }
            }
        }
        return edges;
    }

    private boolean childHasSelfCycle(AtlasVertex processVertex, AtlasVertex currentVertex, boolean isInput) {
        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("childHasSelfCycle");
        Iterator<AtlasEdge> processEdgeIterator;
        processEdgeIterator = processVertex.getEdges(OUT, isInput ? PROCESS_INPUTS_EDGE : PROCESS_OUTPUTS_EDGE).iterator();
        Set<AtlasEdge> processOutputEdges = new HashSet<>();
        while (processEdgeIterator.hasNext()) {
            processOutputEdges.add(processEdgeIterator.next());
        }

        List<AtlasVertex> linkedVertices = processOutputEdges.stream().map(x -> x.getInVertex()).collect(Collectors.toList());
        RequestContext.get().endMetricRecord(metricRecorder);
        return linkedVertices.contains(currentVertex);
    }

    private List<AtlasEdge> getEdgesOfProcess(boolean isInput, AtlasLineageContext lineageContext, AtlasVertex processVertex) {
        if (lineageContext.getIgnoredProcesses() != null &&
                lineageContext.getIgnoredProcesses().contains(processVertex.getProperty(Constants.ENTITY_TYPE_PROPERTY_KEY, String.class))) {
            return Collections.emptyList();
        }

        return vertexEdgeCache.getEdges(processVertex, OUT, isInput ? PROCESS_INPUTS_EDGE : PROCESS_OUTPUTS_EDGE)
                .stream()
                .filter(edge -> shouldProcessEdge(lineageContext, edge) && vertexMatchesEvaluation(edge.getInVertex(), lineageContext))
                .sorted(Comparator.comparing(edge -> edge.getProperty("_r__guid", String.class)))
                .collect(Collectors.toList());
    }

    private boolean vertexMatchesEvaluation(AtlasVertex currentVertex, AtlasLineageContext lineageContext) {
        return currentVertex.equals(lineageContext.getStartDatasetVertex()) || lineageContext.evaluate(currentVertex);
    }

    private boolean shouldProcessEdge(AtlasLineageContext lineageContext, AtlasEdge edge) {
        return lineageContext.isAllowDeletedProcess() ||
                (getStatus(edge.getOutVertex()) == AtlasEntity.Status.ACTIVE && getStateAsString(edge).equals(ACTIVE_STATE_VALUE));
    }

    private List<AtlasEdge> getEdgesOfCurrentVertex(AtlasVertex currentVertex, boolean isInput, AtlasLineageContext lineageContext) {
        return vertexEdgeCache
                .getEdges(currentVertex, IN, isInput ? PROCESS_OUTPUTS_EDGE : PROCESS_INPUTS_EDGE)
                .stream()
                .sorted(Comparator.comparing(edge -> edge.getProperty("_r__guid", String.class)))
                .filter(edge -> shouldProcessEdge(lineageContext, edge))
                .collect(Collectors.toList());
    }

    private boolean lineageContainsEdge(AtlasLineageInfo lineageInfo, AtlasEdge edge) {
        boolean ret = false;

        if (lineageInfo != null && CollectionUtils.isNotEmpty(lineageInfo.getRelations()) && edge != null) {
            String relationGuid = AtlasGraphUtilsV2.getEncodedProperty(edge, RELATIONSHIP_GUID_PROPERTY_KEY, String.class);
            Set<LineageRelation> relations = lineageInfo.getRelations();

            for (LineageRelation relation : relations) {
                if (relation.getRelationshipId().equals(relationGuid)) {
                    ret = true;
                    break;
                }
            }
        }

        return ret;
    }

    private AtlasLineageInfo initializeLineageInfo(String guid, LineageDirection direction, int depth, int limit, int offset) {
        return new AtlasLineageInfo(guid, new HashMap<>(), new HashSet<>(), direction, depth, limit, offset);
    }

    private List executeGremlinScript(Map<String, Object> bindings, String lineageQuery) throws AtlasBaseException {
        List ret;
        ScriptEngine engine = graph.getGremlinScriptEngine();

        try {
            ret = (List) graph.executeGremlinScript(engine, bindings, lineageQuery, false);
        } catch (ScriptException e) {
            throw new AtlasBaseException(INSTANCE_LINEAGE_QUERY_FAILED, lineageQuery);
        } finally {
            graph.releaseGremlinScriptEngine(engine);
        }

        return ret;
    }

    private boolean processVirtualEdge(final AtlasEdge incomingEdge, final AtlasEdge outgoingEdge, AtlasLineageInfo lineageInfo,
                                       AtlasLineageContext lineageContext) throws AtlasBaseException {
        final Map<String, AtlasEntityHeader> entities = lineageInfo.getGuidEntityMap();
        final Set<LineageRelation> relations = lineageInfo.getRelations();

        AtlasVertex inVertex = incomingEdge.getInVertex();
        AtlasVertex outVertex = outgoingEdge.getInVertex();
        AtlasVertex processVertex = outgoingEdge.getOutVertex();
        String inGuid = AtlasGraphUtilsV2.getIdFromVertex(inVertex);
        String outGuid = AtlasGraphUtilsV2.getIdFromVertex(outVertex);
        String processGuid = AtlasGraphUtilsV2.getIdFromVertex(processVertex);
        String relationGuid = null;
        boolean isInputEdge = incomingEdge.getLabel().equalsIgnoreCase(PROCESS_INPUTS_EDGE);

        if (!entities.containsKey(inGuid)) {
            AtlasEntityHeader entityHeader = entityRetriever.toAtlasEntityHeader(inVertex, lineageContext.getAttributes());
            GraphTransactionInterceptor.addToVertexGuidCache(inVertex.getId(), entityHeader.getGuid());
            entities.put(inGuid, entityHeader);
        }

        if (!entities.containsKey(outGuid)) {
            AtlasEntityHeader entityHeader = entityRetriever.toAtlasEntityHeader(outVertex, lineageContext.getAttributes());
            GraphTransactionInterceptor.addToVertexGuidCache(outVertex.getId(), entityHeader.getGuid());
            entities.put(outGuid, entityHeader);
        }

        if (!entities.containsKey(processGuid)) {
            AtlasEntityHeader entityHeader = entityRetriever.toAtlasEntityHeader(processVertex, lineageContext.getAttributes());
            GraphTransactionInterceptor.addToVertexGuidCache(processVertex.getId(), entityHeader.getGuid());
            entities.put(processGuid, entityHeader);
        }

        if (isInputEdge) {
            relations.add(new LineageRelation(inGuid, outGuid, relationGuid, getGuid(processVertex)));
        } else {
            relations.add(new LineageRelation(outGuid, inGuid, relationGuid, getGuid(processVertex)));
        }
        return false;
    }

    private void processEdges(final AtlasEdge incomingEdge, AtlasEdge outgoingEdge, AtlasLineageInfo lineageInfo,
                              AtlasLineageContext lineageContext) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metric = RequestContext.get().startMetricRecord("processEdges");

        final Map<String, AtlasEntityHeader> entities = lineageInfo.getGuidEntityMap();
        final Set<LineageRelation> relations = lineageInfo.getRelations();

        AtlasVertex leftVertex = incomingEdge.getInVertex();
        AtlasVertex processVertex = incomingEdge.getOutVertex();
        AtlasVertex rightVertex = outgoingEdge.getInVertex();

        String leftGuid = AtlasGraphUtilsV2.getIdFromVertex(leftVertex);
        String rightGuid = AtlasGraphUtilsV2.getIdFromVertex(rightVertex);
        String processGuid = AtlasGraphUtilsV2.getIdFromVertex(processVertex);

        if (!entities.containsKey(leftGuid)) {
            AtlasEntityHeader entityHeader = entityRetriever.toAtlasEntityHeaderWithClassifications(leftVertex, lineageContext.getAttributes());
            entities.put(leftGuid, entityHeader);
        }

        if (!entities.containsKey(processGuid)) {
            AtlasEntityHeader entityHeader = entityRetriever.toAtlasEntityHeaderWithClassifications(processVertex, lineageContext.getAttributes());
            entities.put(processGuid, entityHeader);
        }

        if (!entities.containsKey(rightGuid)) {
            AtlasEntityHeader entityHeader = entityRetriever.toAtlasEntityHeaderWithClassifications(rightVertex, lineageContext.getAttributes());
            entities.put(rightGuid, entityHeader);
        }

        String relationGuid = AtlasGraphUtilsV2.getEncodedProperty(incomingEdge, RELATIONSHIP_GUID_PROPERTY_KEY, String.class);
        if (incomingEdge.getLabel().equalsIgnoreCase(PROCESS_INPUTS_EDGE)) {
            relations.add(new LineageRelation(leftGuid, processGuid, relationGuid));
        } else {
            relations.add(new LineageRelation(processGuid, leftGuid, relationGuid));
        }

        relationGuid = AtlasGraphUtilsV2.getEncodedProperty(outgoingEdge, RELATIONSHIP_GUID_PROPERTY_KEY, String.class);
        if (outgoingEdge.getLabel().equalsIgnoreCase(PROCESS_INPUTS_EDGE)) {
            relations.add(new LineageRelation(rightGuid, processGuid, relationGuid));
        } else {
            relations.add(new LineageRelation(processGuid, rightGuid, relationGuid));
        }
        RequestContext.get().endMetricRecord(metric);
    }

    private void processEdge(final AtlasEdge edge, AtlasLineageInfo lineageInfo,
                             AtlasLineageContext lineageContext) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metric = RequestContext.get().startMetricRecord("processEdge");

        final Map<String, AtlasEntityHeader> entities = lineageInfo.getGuidEntityMap();
        final Set<LineageRelation> relations = lineageInfo.getRelations();

        AtlasVertex inVertex = edge.getInVertex();
        AtlasVertex outVertex = edge.getOutVertex();
        String inGuid = AtlasGraphUtilsV2.getIdFromVertex(inVertex);
        String outGuid = AtlasGraphUtilsV2.getIdFromVertex(outVertex);
        String relationGuid = AtlasGraphUtilsV2.getEncodedProperty(edge, RELATIONSHIP_GUID_PROPERTY_KEY, String.class);
        boolean isInputEdge = edge.getLabel().equalsIgnoreCase(PROCESS_INPUTS_EDGE);

        if (!entities.containsKey(inGuid)) {
            AtlasEntityHeader entityHeader = entityRetriever.toAtlasEntityHeaderWithClassifications(inVertex, lineageContext.getAttributes());
            entities.put(inGuid, entityHeader);
        }

        if (!entities.containsKey(outGuid)) {
            AtlasEntityHeader entityHeader = entityRetriever.toAtlasEntityHeaderWithClassifications(outVertex, lineageContext.getAttributes());
            entities.put(outGuid, entityHeader);
        }

        if (isInputEdge) {
            relations.add(new LineageRelation(inGuid, outGuid, relationGuid));
        } else {
            relations.add(new LineageRelation(outGuid, inGuid, relationGuid));
        }
        RequestContext.get().endMetricRecord(metric);
    }

    private void processEdge(final AtlasEdge edge, final Map<String, AtlasEntityHeader> entities,
                             final Set<LineageRelation> relations, AtlasLineageContext lineageContext) throws AtlasBaseException {
        //Backward compatibility method
        AtlasVertex inVertex = edge.getInVertex();
        AtlasVertex outVertex = edge.getOutVertex();
        String inGuid = AtlasGraphUtilsV2.getIdFromVertex(inVertex);
        String outGuid = AtlasGraphUtilsV2.getIdFromVertex(outVertex);
        String relationGuid = AtlasGraphUtilsV2.getEncodedProperty(edge, RELATIONSHIP_GUID_PROPERTY_KEY, String.class);
        boolean isInputEdge = edge.getLabel().equalsIgnoreCase(PROCESS_INPUTS_EDGE);

        if (!entities.containsKey(inGuid)) {
            AtlasEntityHeader entityHeader = entityRetriever.toAtlasEntityHeaderWithClassifications(inVertex, lineageContext.getAttributes());
            entities.put(inGuid, entityHeader);
        }

        if (!entities.containsKey(outGuid)) {
            AtlasEntityHeader entityHeader = entityRetriever.toAtlasEntityHeaderWithClassifications(outVertex, lineageContext.getAttributes());
            entities.put(outGuid, entityHeader);
        }

        if (isInputEdge) {
            relations.add(new LineageRelation(inGuid, outGuid, relationGuid));
        } else {
            relations.add(new LineageRelation(outGuid, inGuid, relationGuid));
        }
    }

    private AtlasLineageInfo getBothLineageInfoV1(AtlasLineageContext lineageContext) throws AtlasBaseException {
        AtlasLineageInfo inputLineage = getLineageInfo(lineageContext, INPUT);
        AtlasLineageInfo outputLineage = getLineageInfo(lineageContext, OUTPUT);
        AtlasLineageInfo ret = inputLineage;

        ret.getRelations().addAll(outputLineage.getRelations());
        ret.getGuidEntityMap().putAll(outputLineage.getGuidEntityMap());
        ret.setLineageDirection(BOTH);

        return ret;
    }

    private String getLineageQuery(String entityGuid, LineageDirection direction, int depth, boolean isDataSet, Map<String, Object> bindings) {
        String incomingFrom = null;
        String outgoingTo = null;
        String ret;

        if (direction.equals(INPUT)) {
            incomingFrom = PROCESS_OUTPUTS_EDGE;
            outgoingTo = PROCESS_INPUTS_EDGE;
        } else if (direction.equals(OUTPUT)) {
            incomingFrom = PROCESS_INPUTS_EDGE;
            outgoingTo = PROCESS_OUTPUTS_EDGE;
        }

        bindings.put("guid", entityGuid);
        bindings.put("incomingEdgeLabel", incomingFrom);
        bindings.put("outgoingEdgeLabel", outgoingTo);
        bindings.put("dataSetDepth", depth);
        bindings.put("processDepth", depth - 1);

        if (depth < 1) {
            ret = isDataSet ? gremlinQueryProvider.getQuery(FULL_LINEAGE_DATASET) :
                    gremlinQueryProvider.getQuery(FULL_LINEAGE_PROCESS);
        } else {
            ret = isDataSet ? gremlinQueryProvider.getQuery(PARTIAL_LINEAGE_DATASET) :
                    gremlinQueryProvider.getQuery(PARTIAL_LINEAGE_PROCESS);
        }

        return ret;
    }
}
