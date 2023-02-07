package org.apache.atlas.discovery;

import org.apache.atlas.model.discovery.SearchParameters;
import org.apache.atlas.model.lineage.LineageOnDemandBaseParams;
import org.apache.atlas.model.lineage.LineageOnDemandConstraints;
import org.apache.atlas.model.lineage.LineageOnDemandRequest;
import org.apache.atlas.repository.graphdb.AtlasVertex;
import org.apache.atlas.type.AtlasTypeRegistry;
import org.apache.commons.collections.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class AtlasLineageOnDemandContext {
    private static final Logger LOG = LoggerFactory.getLogger(AtlasLineageContext.class);

    private Map<String, LineageOnDemandConstraints> constraints;
    private Predicate                               predicate;
    private Set<String>                             attributes;
    private Set<String>                             relationAttributes;
    private LineageOnDemandBaseParams               defaultParams;

    public AtlasLineageOnDemandContext(LineageOnDemandRequest lineageOnDemandRequest, AtlasTypeRegistry typeRegistry) {
        this.constraints = lineageOnDemandRequest.getConstraints();
        this.attributes = lineageOnDemandRequest.getAttributes();
        this.relationAttributes = lineageOnDemandRequest.getRelationAttributes();
        this.defaultParams = lineageOnDemandRequest.getDefaultParams();
        this.predicate = constructInMemoryPredicate(typeRegistry, lineageOnDemandRequest.getTraversalFilters());
    }

    public Map<String, LineageOnDemandConstraints> getConstraints() {
        return constraints;
    }

    public void setConstraints(Map<String, LineageOnDemandConstraints> constraints) {
        this.constraints = constraints;
    }

    public Predicate getPredicate() {
        return predicate;
    }

    public void setPredicate(Predicate predicate) {
        this.predicate = predicate;
    }

    public Set<String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Set<String> attributes) {
        this.attributes = attributes;
    }

    public Set<String> getRelationAttributes() {
        return relationAttributes;
    }

    public void setRelationAttributes(Set<String> relationAttributes) {
        this.relationAttributes = relationAttributes;
    }

    public LineageOnDemandBaseParams getDefaultParams() {
        return defaultParams;
    }

    public void setDefaultParams(LineageOnDemandBaseParams defaultParams) {
        this.defaultParams = defaultParams;
    }

    protected Predicate constructInMemoryPredicate(AtlasTypeRegistry typeRegistry, SearchParameters.FilterCriteria filterCriteria) {
        LineageSearchProcessor lineageSearchProcessor = new LineageSearchProcessor();
        return lineageSearchProcessor.constructInMemoryPredicate(typeRegistry, filterCriteria);
    }

    protected boolean evaluate(AtlasVertex vertex) {
        if (predicate != null) {
            return predicate.evaluate(vertex);
        }
        return true;
    }
}
