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
package org.apache.atlas.repository.store.graph.v2.preprocessor.glossary;


import org.apache.atlas.AtlasErrorCode;
import org.apache.atlas.RequestContext;
import org.apache.atlas.authorize.AtlasAuthorizationUtils;
import org.apache.atlas.authorize.AtlasEntityAccessRequest;
import org.apache.atlas.authorize.AtlasPrivilege;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.model.instance.*;
import org.apache.atlas.repository.graph.GraphHelper;
import org.apache.atlas.repository.graphdb.AtlasEdge;
import org.apache.atlas.repository.graphdb.AtlasEdgeDirection;
import org.apache.atlas.repository.graphdb.AtlasGraph;
import org.apache.atlas.repository.graphdb.AtlasVertex;
import org.apache.atlas.repository.store.graph.AtlasRelationshipStore;
import org.apache.atlas.repository.store.graph.v1.DeleteHandlerDelegate;
import org.apache.atlas.repository.store.graph.v2.*;
import org.apache.atlas.repository.store.graph.v2.preprocessor.PreProcessor;
import org.apache.atlas.type.*;
import org.apache.atlas.utils.AtlasEntityUtil;
import org.apache.atlas.utils.AtlasPerfMetrics;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

import static org.apache.atlas.model.instance.AtlasRelatedObjectId.KEY_RELATIONSHIP_ATTRIBUTES;
import static org.apache.atlas.model.instance.EntityMutations.EntityOperation.UPDATE;
import static org.apache.atlas.repository.Constants.*;
import static org.apache.atlas.repository.Constants.ACTIVE_STATE_VALUE;
import static org.apache.atlas.repository.store.graph.v2.preprocessor.PreProcessorUtils.*;
import static org.apache.atlas.type.AtlasStructType.AtlasAttribute.AtlasRelationshipEdgeDirection.IN;

public class CategoryPreProcessor implements PreProcessor {
    private static final Logger LOG = LoggerFactory.getLogger(CategoryPreProcessor.class);

    private final AtlasTypeRegistry typeRegistry;
    private final EntityGraphRetriever entityRetriever;
    private final GraphHelper graphHelper;
    private final DeleteHandlerDelegate deleteDelegate;
    private final AtlasGraph graph;
    private final AtlasRelationshipStore relationshipStore;

    private AtlasEntityHeader anchor;
    private AtlasEntityHeader parentCategory;

    public CategoryPreProcessor(AtlasTypeRegistry typeRegistry, EntityGraphRetriever entityRetriever, GraphHelper graphHelper, DeleteHandlerDelegate deleteDelegate, AtlasGraph graph, AtlasRelationshipStore relationshipStore) {
        this.entityRetriever = entityRetriever;
        this.typeRegistry = typeRegistry;
        this.graphHelper = graphHelper;
        this.deleteDelegate = deleteDelegate;
        this.graph = graph;
        this.relationshipStore = relationshipStore;
    }

    @Override
    public void processAttributes(AtlasStruct entityStruct, EntityMutationContext context,
                                  EntityMutations.EntityOperation operation) throws AtlasBaseException {
        //Handle name & qualifiedName
        if (LOG.isDebugEnabled()) {
            LOG.debug("CategoryPreProcessor.processAttributes: pre processing {}, {}",
                    entityStruct.getAttribute(QUALIFIED_NAME), operation);
        }

        AtlasEntity entity = (AtlasEntity) entityStruct;
        AtlasVertex vertex = context.getVertex(entity.getGuid());

        setAnchorAndParent(entity, context);

        switch (operation) {
            case CREATE:
                processCreateCategory(entity, vertex);
                break;
            case UPDATE:
                processUpdateCategory(entity, vertex, context);
                break;
        }
    }

    private void processCreateCategory(AtlasEntity entity, AtlasVertex vertex) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("processCreateCategory");
        String catName = (String) entity.getAttribute(NAME);

        if (StringUtils.isEmpty(catName) || isNameInvalid(catName)) {
            throw new AtlasBaseException(AtlasErrorCode.INVALID_DISPLAY_NAME);
        }

        if (parentCategory != null) {
            AtlasEntity newParent = entityRetriever.toAtlasEntity(parentCategory.getGuid());
            AtlasRelatedObjectId newAnchor = (AtlasRelatedObjectId) newParent.getRelationshipAttribute(ANCHOR);

            if (newAnchor != null && !newAnchor.getGuid().equals(anchor.getGuid())){
                throw new AtlasBaseException(AtlasErrorCode.CATEGORY_PARENT_FROM_OTHER_GLOSSARY);
            }
        }

        entity.setAttribute(QUALIFIED_NAME, createQualifiedName(vertex));
        AtlasAuthorizationUtils.verifyAccess(new AtlasEntityAccessRequest(typeRegistry, AtlasPrivilege.ENTITY_CREATE, new AtlasEntityHeader(entity)),
                "create entity: type=", entity.getTypeName());

        validateChildren(entity, null);

        RequestContext.get().endMetricRecord(metricRecorder);
    }

    private void processUpdate(AtlasEntity entity, AtlasVertex vertex, EntityMutationContext context) throws AtlasBaseException {

        AtlasEntityType entityType      = typeRegistry.getEntityTypeByName(entity.getTypeName());
        AtlasObjectId newParentObjectId = (AtlasObjectId) entity.getRelationshipAttribute(ANCHOR);
        String relationshipType         = AtlasEntityUtil.getRelationshipType(newParentObjectId);
        AtlasStructType.AtlasAttribute parentAttribute  = entityType.getRelationshipAttribute(ANCHOR, relationshipType);
        AtlasObjectId currentParentObjectId = (AtlasObjectId) entityRetriever.getEntityAttribute(vertex, parentAttribute);
        AtlasVertex currentParentVertex         = entityRetriever.getEntityVertex(currentParentObjectId);
        String currentAnchorQualifiedName = currentParentVertex.getProperty(QUALIFIED_NAME, String.class);
        //Qualified name of the category/term will not be updated if anchor is not changed
        String qualifiedName      = vertex.getProperty(QUALIFIED_NAME, String.class);
        entity.setAttribute(QUALIFIED_NAME, qualifiedName);
        String newAnchorQualifiedName = updateTermResourceAttributes(typeRegistry, entityRetriever, entity, vertex, context);

        if(StringUtils.isNotEmpty(newAnchorQualifiedName) && !currentAnchorQualifiedName.equals(newAnchorQualifiedName)) {
            processParentAnchorUpdation(entity, vertex, currentAnchorQualifiedName, newAnchorQualifiedName);
            LOG.debug("Moved folder {} from collection {} to collection {}", entity.getAttribute(QUALIFIED_NAME), currentAnchorQualifiedName, newAnchorQualifiedName);
        }

    }


    private void processParentAnchorUpdation(AtlasEntity entity, AtlasVertex categoryVertex, String currentAnchorQualifiedName, String newAnchorQualifiedName) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder categroyProcessMetric = RequestContext.get().startMetricRecord("processParentAnchorUpdation");

        String categoryQualifiedName        = categoryVertex.getProperty(QUALIFIED_NAME, String.class);
        String updatedCategoryQualifiedName = categoryQualifiedName.replaceAll(currentAnchorQualifiedName, newAnchorQualifiedName);

        /**
         * 1. Move all the terms to new anchor first
         * 2. Move all the child categories to new anchor
         * 3. Update the qualified name of current category
         * 4. Recursively find the child categories and move child terms to new glossary
         */
        moveTermsToDifferentAnchor(entity, categoryVertex, currentAnchorQualifiedName, newAnchorQualifiedName, updatedCategoryQualifiedName);

        Iterator<AtlasVertex> childrenCategories = getActiveChildren(categoryVertex, CATEGORY_PARENT_EDGE_LABEL);

        while (childrenCategories.hasNext()) {
            AtlasVertex nestedCategoryVertex = childrenCategories.next();

            AtlasEntity categoryEntity = entityRetriever.toAtlasEntity(categoryVertex);
            AtlasObjectId parentCategory = (AtlasObjectId) categoryEntity.getRelationshipAttribute(PARENT_CATEGORY);
            if(parentCategory != null && parentCategory.getGuid().equals(nestedCategoryVertex.getProperty(GUID_PROPERTY_KEY, String.class))){
                return;
            }

            if (nestedCategoryVertex != null){// && (parentCategory != null && parentCategory.getGuid().equals(nestedCategroyVertex.getProperty(GUID_PROPERTY_KEY, String.class)))) {
                updateChildAttributesOnUpdatingAnchor(entity, nestedCategoryVertex, currentAnchorQualifiedName, newAnchorQualifiedName, updatedCategoryQualifiedName);
                /**
                 * Recursively find the child folders and move child queries to new collection
                 * folder1 -> folder2 -> query1
                 * When we will move folder1 to new collection, recursively it will find folder2
                 * Then it will move all the children of folder2 also to new collection
                 */
                processParentAnchorUpdation(entity, nestedCategoryVertex, currentAnchorQualifiedName, newAnchorQualifiedName);

                LOG.info("Moved nested folder into new collection {}", newAnchorQualifiedName);
            }
        }

        LOG.info("Moved current folder with qualified name {} into new collection {}", categoryQualifiedName, newAnchorQualifiedName);

        RequestContext.get().endMetricRecord(categroyProcessMetric);
    }

    private void moveTermsToDifferentAnchor(AtlasEntity entity, AtlasVertex categoryVertex, String currentAnchorQualifiedName,
                                                  String newAnchorQualifiedName, String categoryQualifiedName) throws AtlasBaseException {

        AtlasPerfMetrics.MetricRecorder termProcessMetric = RequestContext.get().startMetricRecord("moveTermsToDifferentCollection");
        Iterator<AtlasVertex> childrenTermsIterator = getActiveChildren(categoryVertex, CATEGORY_TERMS_EDGE_LABEL);

        //Update all the children terms attribute
        while (childrenTermsIterator.hasNext()) {
            AtlasVertex termVertex = childrenTermsIterator.next();
            if(termVertex != null) {
                updateChildAttributesOnUpdatingAnchor(entity, termVertex, currentAnchorQualifiedName,
                        newAnchorQualifiedName, categoryQualifiedName);
            }
        }

        RequestContext.get().endMetricRecord(termProcessMetric);
    }

    private static Map<String, Object> getRelationshipAttributes(Object val) throws AtlasBaseException {
        if (val instanceof AtlasRelatedObjectId) {
            AtlasStruct relationshipStruct = ((AtlasRelatedObjectId) val).getRelationshipAttributes();

            return (relationshipStruct != null) ? relationshipStruct.getAttributes() : null;
        } else if (val instanceof Map) {
            Object relationshipStruct = ((Map) val).get(KEY_RELATIONSHIP_ATTRIBUTES);

            if (relationshipStruct instanceof Map) {
                return AtlasTypeUtil.toStructAttributes(((Map) relationshipStruct));
            }
        }

        return null;
    }

    private static String getRelationshipGuid(Object val) throws AtlasBaseException {
        if (val instanceof AtlasRelatedObjectId) {
            return ((AtlasRelatedObjectId) val).getRelationshipGuid();
        } else if (val instanceof Map) {
            Object relationshipGuidVal = ((Map) val).get(AtlasRelatedObjectId.KEY_RELATIONSHIP_GUID);

            return relationshipGuidVal != null ? relationshipGuidVal.toString() : null;
        }

        return null;
    }

    private void updateChildAttributesOnUpdatingAnchor(AtlasEntity entity, AtlasVertex childVertex,  String currentAnchorQualifiedName, String newAnchorQualifiedName,
                                                           String categoryQualifiedName) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("updateChildAttributesOnUpdatingAnchor");
        Map<String, Object> updatedAttributes = new HashMap<>();
        String qualifiedName            =   childVertex.getProperty(QUALIFIED_NAME, String.class);
        String updatedQualifiedName     =   qualifiedName.replaceAll(currentAnchorQualifiedName, newAnchorQualifiedName);
        String typeName = childVertex.getProperty(TYPE_NAME_PROPERTY_KEY,String.class);
        AtlasEntityType entityType = typeRegistry.getEntityTypeByName(typeName);
        for(String attrName : entityType.getRelationshipAttributes().keySet()) {
            Object attrValue = entity.getRelationshipAttribute(attrName);
            String relationType = "";
            if (attrValue != null) relationType = AtlasEntityUtil.getRelationshipType(attrValue);

            if (attrName.equals("anchor") && typeName.equals("AtlasGlossaryTerm"))
                relationType = GLOSSARY_TERMS_EDGE_LABEL;
            else if (attrName.equals("anchor")) relationType = GLOSSARY_CATEGORY_EDGE_LABEL;

            if (StringUtils.isNotEmpty(relationType)) {
                AtlasStructType.AtlasAttribute attribute = entityType.getRelationshipAttribute(attrName, relationType);
                AttributeMutationContext ctx = new AttributeMutationContext(UPDATE, childVertex, attribute, attrValue);
                AtlasStructType.AtlasAttribute.AtlasRelationshipEdgeDirection edgeDirection = ctx.getAttribute().getRelationshipEdgeDirection();
                String edgeLabel = ctx.getAttribute().getRelationshipEdgeLabel();

                // if relationshipDefs doesn't exist, use legacy way of finding edge label.
                if (org.apache.commons.lang3.StringUtils.isEmpty(edgeLabel)) {
                    edgeLabel = AtlasGraphUtilsV2.getEdgeLabel(ctx.getVertexProperty());
                }

                String relationshipGuid = getRelationshipGuid(ctx.getValue());
                AtlasEdge currentEdge;

                // if relationshipGuid is assigned in AtlasRelatedObjectId use it to fetch existing AtlasEdge
                if (org.apache.commons.lang3.StringUtils.isNotEmpty(relationshipGuid) && !RequestContext.get().isImportInProgress()) {
                    currentEdge = graphHelper.getEdgeForGUID(relationshipGuid);
                } else {
                    currentEdge = graphHelper.getEdgeForLabel(ctx.getReferringVertex(), edgeLabel, edgeDirection);
                }

                deleteDelegate.getHandler().deleteEdgeReference(currentEdge, ctx.getAttrType().getTypeCategory(), false, true, ctx.getReferringVertex());

                AtlasObjectId anchor = (AtlasObjectId) entity.getRelationshipAttribute("anchor");
                AtlasVertex entityVertex = AtlasGraphUtilsV2.findByGuid(this.graph, anchor.getGuid());

                String relationshipName = attribute.getRelationshipName();
                AtlasVertex toVertex;
                AtlasVertex fromVertex;
                if (attribute.getRelationshipEdgeDirection() == IN) {
                    fromVertex = entityVertex;
                    toVertex = childVertex;

                } else {
                    fromVertex = childVertex;
                    toVertex = entityVertex;
                }
                Map<String, Object> relationshipAttributes = getRelationshipAttributes(ctx.getValue());

                AtlasEdge newEdge = relationshipStore.getOrCreate(fromVertex, toVertex, new AtlasRelationship(relationshipName, relationshipAttributes));
                if (RequestContext.get().isImportInProgress()) {
                    String relationshipGuid1 = getRelationshipGuid(ctx.getValue());

                    if (!org.apache.commons.lang3.StringUtils.isEmpty(relationshipGuid1)) {
                        AtlasGraphUtilsV2.setEncodedProperty(newEdge, RELATIONSHIP_GUID_PROPERTY_KEY, relationshipGuid1);
                    }
                }

            }
        }

        if (!qualifiedName.equals(updatedQualifiedName)) {
            AtlasGraphUtilsV2.setEncodedProperty(childVertex, QUALIFIED_NAME, updatedQualifiedName);
            updatedAttributes.put(QUALIFIED_NAME, updatedQualifiedName);
        }

        recordUpdatedChildEntities(childVertex, updatedAttributes);

        RequestContext.get().endMetricRecord(metricRecorder);
    }

    private void recordUpdatedChildEntities(AtlasVertex entityVertex, Map<String, Object> updatedAttributes) {
        RequestContext requestContext = RequestContext.get();
        AtlasPerfMetrics.MetricRecorder metricRecorder = requestContext.startMetricRecord("recordUpdatedChildEntities");
        AtlasEntity entity = new AtlasEntity();
        entity = entityRetriever.mapSystemAttributes(entityVertex, entity);
        entity.setAttributes(updatedAttributes);
        requestContext.cacheDifferentialEntity(new AtlasEntity(entity));

        AtlasEntityType entityType = typeRegistry.getEntityTypeByName(entity.getTypeName());

        //Add the min info attributes to entity header to be sent as part of notification
        if(entityType != null) {
            AtlasEntity finalEntity = entity;
            entityType.getMinInfoAttributes().values().stream().filter(attribute -> !updatedAttributes.containsKey(attribute.getName())).forEach(attribute -> {
                Object attrValue = null;
                try {
                    attrValue = entityRetriever.getVertexAttribute(entityVertex, attribute);
                } catch (AtlasBaseException e) {
                    LOG.error("Error while getting vertex attribute", e);
                }
                if(attrValue != null) {
                    finalEntity.setAttribute(attribute.getName(), attrValue);
                }
            });
            requestContext.recordEntityUpdate(new AtlasEntityHeader(finalEntity));
        }

        requestContext.endMetricRecord(metricRecorder);
    }

    private Iterator<AtlasVertex> getActiveChildren(AtlasVertex childVertex, String childrenEdgeLabel) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("getActiveChildren");
        try {
            return childVertex.query()
                    .direction(AtlasEdgeDirection.BOTH)
                    .label(childrenEdgeLabel)
                    .has(STATE_PROPERTY_KEY, ACTIVE_STATE_VALUE)
                    .vertices()
                    .iterator();
        } catch (Exception e) {
            LOG.error("Error while getting active children of category", e);
            throw new AtlasBaseException(AtlasErrorCode.INTERNAL_ERROR, e);
        }
        finally {
            RequestContext.get().endMetricRecord(metricRecorder);
        }

    }

    private void processUpdateCategory(AtlasEntity entity, AtlasVertex vertex, EntityMutationContext context) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("processUpdateCategory");
        String catName = (String) entity.getAttribute(NAME);

        if (StringUtils.isEmpty(catName) || isNameInvalid(catName)) {
            throw new AtlasBaseException(AtlasErrorCode.INVALID_DISPLAY_NAME);
        }

        AtlasEntity storeObject = entityRetriever.toAtlasEntity(vertex);
        AtlasRelatedObjectId existingAnchor = (AtlasRelatedObjectId) storeObject.getRelationshipAttribute(ANCHOR);
        if (existingAnchor != null && !existingAnchor.getGuid().equals(anchor.getGuid())){
            processUpdate(entity, vertex, context);
        } else{
            String vertexQnName = vertex.getProperty(QUALIFIED_NAME, String.class);
            entity.setAttribute(QUALIFIED_NAME, vertexQnName);
        }

        if (parentCategory != null) {
            AtlasEntity newParent = entityRetriever.toAtlasEntity(parentCategory.getGuid());
            AtlasRelatedObjectId newAnchor = (AtlasRelatedObjectId) newParent.getRelationshipAttribute(ANCHOR);

            if (newAnchor != null && !newAnchor.getGuid().equals(existingAnchor.getGuid())){
                throw new AtlasBaseException(AtlasErrorCode.CATEGORY_PARENT_FROM_OTHER_GLOSSARY);
            }
        }

        validateChildren(entity, storeObject);
        RequestContext.get().endMetricRecord(metricRecorder);
    }

    private void validateChildren(AtlasEntity entity, AtlasEntity storeObject) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("CategoryPreProcessor.validateChildren");
        List<AtlasObjectId> existingChildren = new ArrayList<>();
        if (storeObject != null) {
            existingChildren = (List<AtlasObjectId>) storeObject.getRelationshipAttribute(CATEGORY_CHILDREN);
        }
        Set<String> existingChildrenGuids = existingChildren.stream().map(x -> x.getGuid()).collect(Collectors.toSet());

        List<AtlasObjectId> children = (List<AtlasObjectId>) entity.getRelationshipAttribute(CATEGORY_CHILDREN);

        if (CollectionUtils.isNotEmpty(children)) {
            for (AtlasObjectId child : children) {
                if (!existingChildrenGuids.contains(child.getGuid())) {
                    AtlasEntity newChild = entityRetriever.toAtlasEntity(child.getGuid());
                    AtlasRelatedObjectId newAnchor = (AtlasRelatedObjectId) newChild.getRelationshipAttribute(ANCHOR);

                    if (newAnchor != null && !newAnchor.getGuid().equals(anchor.getGuid())){
                        throw new AtlasBaseException(AtlasErrorCode.CATEGORY_PARENT_FROM_OTHER_GLOSSARY);
                    }
                }
            }
        }
        RequestContext.get().endMetricRecord(metricRecorder);
    }

    private void setAnchorAndParent(AtlasEntity entity, EntityMutationContext context) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("CategoryPreProcessor.setAnchorAndParent");
        if (anchor == null) {
            AtlasObjectId objectId = (AtlasObjectId) entity.getRelationshipAttribute(ANCHOR);

            if (StringUtils.isNotEmpty(objectId.getGuid())) {
                AtlasVertex vertex = context.getVertex(objectId.getGuid());

                if (vertex == null) {
                    anchor = entityRetriever.toAtlasEntityHeader(objectId.getGuid());
                } else {
                    anchor = entityRetriever.toAtlasEntityHeader(vertex);
                }

            } else if (MapUtils.isNotEmpty(objectId.getUniqueAttributes()) &&
                    StringUtils.isNotEmpty( (String) objectId.getUniqueAttributes().get(QUALIFIED_NAME))) {
                anchor = new AtlasEntityHeader(objectId.getTypeName(), objectId.getUniqueAttributes());

            }
        }

        if (parentCategory == null) {
            AtlasObjectId objectId = (AtlasObjectId) entity.getRelationshipAttribute(CATEGORY_PARENT);

            if (objectId != null) {
                if (StringUtils.isNotEmpty(objectId.getGuid())) {
                    AtlasVertex vertex = context.getVertex(objectId.getGuid());

                    if (vertex == null) {
                        parentCategory = entityRetriever.toAtlasEntityHeader(objectId.getGuid());
                    } else {
                        parentCategory = entityRetriever.toAtlasEntityHeader(vertex);
                    }

                } else if (MapUtils.isNotEmpty(objectId.getUniqueAttributes()) &&
                        StringUtils.isNotEmpty( (String) objectId.getUniqueAttributes().get(QUALIFIED_NAME))) {
                    parentCategory = new AtlasEntityHeader(objectId.getTypeName(), objectId.getUniqueAttributes());

                }
            }
        }
        RequestContext.get().endMetricRecord(metricRecorder);
    }

    private String createQualifiedName(AtlasVertex vertex) {

        if (vertex != null) {
            String catQName = vertex.getProperty(QUALIFIED_NAME, String.class);
            if (StringUtils.isNotEmpty(catQName)) {
                return catQName;
            }
        }

        return getUUID() + "@" + anchor.getAttribute(QUALIFIED_NAME);
    }
}
