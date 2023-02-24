package org.apache.atlas.repository.store.graph.v2.preprocessor.readme;

import org.apache.atlas.RequestContext;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasObjectId;
import org.apache.atlas.model.instance.AtlasStruct;
import org.apache.atlas.model.instance.EntityMutations;
import org.apache.atlas.repository.graph.GraphHelper;
import org.apache.atlas.repository.graphdb.AtlasGraph;
import org.apache.atlas.repository.graphdb.AtlasVertex;
import org.apache.atlas.repository.store.graph.v2.AtlasGraphUtilsV2;
import org.apache.atlas.repository.store.graph.v2.EntityGraphRetriever;
import org.apache.atlas.repository.store.graph.v2.EntityMutationContext;
import org.apache.atlas.repository.store.graph.v2.preprocessor.PreProcessor;
import org.apache.atlas.repository.store.graph.v2.preprocessor.glossary.GlossaryPreProcessor;
import org.apache.atlas.type.AtlasEntityType;
import org.apache.atlas.type.AtlasTypeRegistry;
import org.apache.atlas.utils.AtlasPerfMetrics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.atlas.repository.Constants.QUALIFIED_NAME;

public class ReadmePreProcessor implements PreProcessor {
    private static final Logger LOG = LoggerFactory.getLogger(GlossaryPreProcessor.class);

    private final AtlasTypeRegistry typeRegistry;
    private final EntityGraphRetriever entityRetriever;
    private final AtlasGraph graph;

    public ReadmePreProcessor(AtlasTypeRegistry typeRegistry, EntityGraphRetriever entityRetriever, AtlasGraph graph) {
        this.entityRetriever = entityRetriever;
        this.typeRegistry = typeRegistry;
        this.graph = graph;
    }

    @Override
    public void processAttributes(AtlasStruct entityStruct, EntityMutationContext context,
                                  EntityMutations.EntityOperation operation) throws AtlasBaseException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("GlossaryPreProcessor.processAttributes: pre processing {}, {}", entityStruct.getAttribute(QUALIFIED_NAME), operation);
        }

        AtlasEntity entity = (AtlasEntity) entityStruct;

        switch (operation) {
            case CREATE:
                processCreateReadme(entity, context);
                break;
            case UPDATE:
                processUpdateReadme(entity, context.getVertex(entity.getGuid()));
                break;
        }
    }

    private void processCreateReadme(AtlasEntity entity, EntityMutationContext context) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("processCreateReadme");
        String entityQualifiedName = createQualifiedName(entity);

        entity.setAttribute(QUALIFIED_NAME, entityQualifiedName);

        AtlasEntityType entityType = typeRegistry.getEntityTypeByName(entity.getTypeName());
        AtlasVertex vertex = AtlasGraphUtilsV2.findByUniqueAttributes(this.graph, entityType, entity.getAttributes());
        if(vertex != null){
            String guidOfExistingReadme = GraphHelper.getGuid(vertex);
            entity.setGuid(guidOfExistingReadme);
            context.cacheEntity(guidOfExistingReadme, vertex, entityType);
        }

        RequestContext.get().endMetricRecord(metricRecorder);
    }
    private void processUpdateReadme(AtlasStruct entity, AtlasVertex vertex){

        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("processUpdateReadme");
        String vertexQnName = vertex.getProperty(QUALIFIED_NAME, String.class);

        entity.setAttribute(QUALIFIED_NAME, vertexQnName);
        RequestContext.get().endMetricRecord(metricRecorder);
    }

    public static String createQualifiedName(AtlasEntity entity) {
        AtlasObjectId asset = (AtlasObjectId) entity.getRelationshipAttribute("asset");
        return asset.getGuid() + "/readme" ;
    }
}
