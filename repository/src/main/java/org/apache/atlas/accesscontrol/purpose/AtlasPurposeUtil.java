package org.apache.atlas.accesscontrol.purpose;

import org.apache.atlas.AtlasConfiguration;
import org.apache.atlas.accesscontrol.AccessControlUtil;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.model.discovery.IndexSearchParams;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasEntityHeader;
import org.apache.atlas.ranger.AtlasRangerService;
import org.apache.atlas.repository.graphdb.AtlasGraph;
import org.apache.commons.collections.CollectionUtils;
import org.apache.ranger.plugin.model.RangerPolicy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


public class AtlasPurposeUtil extends AccessControlUtil {

    public static final String LABEL_PREFIX_PURPOSE        = "purpose:";
    public static final String LABEL_PREFIX_PURPOSE_POLICY = "purpose:policy:";

    public static final String RESOURCE_TAG = "tag";
    public static final String SERVICE_NAME = AtlasConfiguration.RANGER_ATLAS_SERVICE_TYPE.getString();


    public static final Set<String> POLICY_ACTIONS = new HashSet<String>() {{
        add("type-read");
        add("type-create");
        add("type-update");
        add("type-delete");

        add("entity-read");
        add("entity-create");
        add("entity-update");
        add("entity-delete");

        add("entity-add-classification");
        add("entity-update-classification");
        add("entity-remove-classification");

        add("add-relationship");
        add("update-relationship");
        add("remove-relationship");

        add("entity-add-label");
        add("entity-remove-label");

        add("entity-update-business-metadata");

        add("admin-purge");
        add("admin-export");
        add("admin-import");
        add("admin-audits");
        add("admin-entity-audits");

        add("select");
    }};

    public static List<String> getTags(AtlasEntity purpose) {
        return (List<String>) purpose.getAttribute(ATTR_PURPOSE_TAGS);
    }

    public static List<String> getTags(AtlasEntityHeader purpose) {
        return (List<String>) purpose.getAttribute(ATTR_PURPOSE_TAGS);
    }

    public static boolean getIsAllUsers(AtlasEntity policy) {
        if (policy.hasAttribute(ATTR_ALL_USERS)) {
            return (boolean) policy.getAttribute(ATTR_ALL_USERS);
        } else {
            return false;
        }
    }

    public static String getPurposeLabel(String purposeGuid) {
        return LABEL_PREFIX_PURPOSE + purposeGuid;
    }

    public static String getPurposePolicyLabel(String purposePolicyGuid) {
        return LABEL_PREFIX_PURPOSE_POLICY + purposePolicyGuid;
    }

    public static List<String> getLabelsForPurposePolicy(String purposeGuid, String purposePolicyGuid) {
        return Arrays.asList(getPurposeLabel(purposeGuid), getPurposePolicyLabel(purposePolicyGuid), "type:purpose");
    }

    protected static String formatAccessType(String type){
        return formatAccessType(SERVICE_NAME, type);
    }

    protected static String formatMaskType(String type){
        return formatAccessType("heka", type);
    }

    protected static String formatAccessType(String prefix, String type){
        return String.format("%s:%s", prefix, type);
    }

    public static void validateUniquenessByTags(AtlasGraph graph, List<String> tags, String typeName) throws AtlasBaseException {
        IndexSearchParams indexSearchParams = new IndexSearchParams();
        Map<String, Object> dsl = mapOf("size", 1);

        List mustClauseList = new ArrayList();
        mustClauseList.add(mapOf("term", mapOf("__typeName.keyword", typeName)));
        mustClauseList.add(mapOf("term", mapOf("__state", "ACTIVE")));
        mustClauseList.add(mapOf("terms", mapOf(ATTR_PURPOSE_TAGS, tags)));

        Map<String, Object> scriptMap = mapOf("inline", "doc['" + ATTR_PURPOSE_TAGS + "'].length == params.list_length");
        scriptMap.put("lang", "painless");
        scriptMap.put("params", mapOf("list_length", tags.size()));

        mustClauseList.add(mapOf("script", mapOf("script", scriptMap)));

        dsl.put("query", mapOf("bool", mapOf("must", mustClauseList)));

        indexSearchParams.setDsl(dsl);

        if (hasMatchingVertex(graph, tags, indexSearchParams)){
            throw new AtlasBaseException(String.format("Entity already exists, typeName:tags, %s:%s", typeName, tags));
        }
    }

    public static List<RangerPolicy> fetchRangerPoliciesByResourcesForPurposeDelete(AtlasRangerService atlasRangerService,
                                                                                    AtlasEntity purpose) throws AtlasBaseException {
        List<RangerPolicy> rangerPolicies = new ArrayList<>();
        List<RangerPolicy> ret = new ArrayList<>();

        Map <String, String> params = new HashMap<>();
        int size = 25;
        int from = 0;

        params.put("page", "0");
        params.put("pageSize", String.valueOf(size));
        params.put("serviceType", "tag");
        List<String> tags = getTags(purpose);

        int fetched;
        do {
            params.put("startIndex", String.valueOf(from));

            List<RangerPolicy> rangerPoliciesPaginated = atlasRangerService.getPoliciesByResources(getResourcesForPurposeDelete(tags.get(0)), params);
            fetched = rangerPoliciesPaginated.size();
            rangerPolicies.addAll(rangerPoliciesPaginated);

            from += size;

        } while (fetched == size);

        if (CollectionUtils.isNotEmpty(rangerPolicies)) {
            //find exact matches among the result list
            for (RangerPolicy policy : rangerPolicies) {
                List<String> policyTags = policy.getResources().get(RESOURCE_TAG).getValues();

                if (CollectionUtils.isEqualCollection(policyTags, tags)) {
                    ret.add(policy);
                }
            }
        }

        return ret;
    }

    private static Map<String, String> getResourcesForPurposeDelete(String tag) {
        Map<String, String> resources = new HashMap<>();
        resources.put(RESOURCE_TAG, tag);

        return resources;
    }
}