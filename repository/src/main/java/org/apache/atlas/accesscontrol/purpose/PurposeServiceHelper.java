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
package org.apache.atlas.accesscontrol.purpose;

import org.apache.atlas.RequestContext;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasObjectId;
import org.apache.atlas.repository.graphdb.AtlasGraph;
import org.apache.atlas.utils.AtlasPerfMetrics;
import org.apache.commons.collections.CollectionUtils;
import org.apache.ranger.plugin.model.RangerPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.apache.atlas.AtlasErrorCode.BAD_REQUEST;
import static org.apache.atlas.AtlasErrorCode.OPERATION_NOT_SUPPORTED;
import static org.apache.atlas.AtlasErrorCode.POLICY_ALREADY_EXISTS;
import static org.apache.atlas.accesscontrol.AccessControlUtil.ACCESS_ADD_REL;
import static org.apache.atlas.accesscontrol.AccessControlUtil.ACCESS_REMOVE_REL;
import static org.apache.atlas.accesscontrol.AccessControlUtil.ACCESS_UPDATE_REL;
import static org.apache.atlas.accesscontrol.AccessControlUtil.ATTR_DATA_MASKING;
import static org.apache.atlas.accesscontrol.AccessControlUtil.ATTR_POLICY_ACTIONS;
import static org.apache.atlas.accesscontrol.AccessControlUtil.LINK_ASSET_ACTION;
import static org.apache.atlas.accesscontrol.AccessControlUtil.RANGER_MASK_NONE;
import static org.apache.atlas.accesscontrol.AccessControlUtil.REL_ATTR_ACCESS_CONTROL;
import static org.apache.atlas.accesscontrol.AccessControlUtil.getActions;
import static org.apache.atlas.accesscontrol.AccessControlUtil.getDataPolicyMaskType;
import static org.apache.atlas.accesscontrol.AccessControlUtil.getIsAllow;
import static org.apache.atlas.accesscontrol.AccessControlUtil.getName;
import static org.apache.atlas.accesscontrol.AccessControlUtil.getPolicies;
import static org.apache.atlas.accesscontrol.AccessControlUtil.getPolicyCategory;
import static org.apache.atlas.accesscontrol.AccessControlUtil.getPolicyGroups;
import static org.apache.atlas.accesscontrol.AccessControlUtil.getPolicyType;
import static org.apache.atlas.accesscontrol.AccessControlUtil.getPolicyUsers;
import static org.apache.atlas.accesscontrol.AccessControlUtil.isDataMaskPolicy;
import static org.apache.atlas.accesscontrol.AccessControlUtil.isDataPolicy;
import static org.apache.atlas.accesscontrol.AccessControlUtil.validateUniquenessByName;
import static org.apache.atlas.accesscontrol.purpose.AtlasPurposeUtil.POLICY_ACTIONS;
import static org.apache.atlas.accesscontrol.purpose.AtlasPurposeUtil.RESOURCE_TAG;
import static org.apache.atlas.accesscontrol.purpose.AtlasPurposeUtil.formatAccessType;
import static org.apache.atlas.accesscontrol.purpose.AtlasPurposeUtil.formatMaskType;
import static org.apache.atlas.accesscontrol.purpose.AtlasPurposeUtil.getIsAllUsers;
import static org.apache.atlas.accesscontrol.purpose.AtlasPurposeUtil.getPurposeLabel;
import static org.apache.atlas.accesscontrol.purpose.AtlasPurposeUtil.getPurposePolicyLabel;
import static org.apache.atlas.accesscontrol.purpose.AtlasPurposeUtil.getTags;
import static org.apache.atlas.accesscontrol.purpose.AtlasPurposeUtil.validateUniquenessByTags;
import static org.apache.atlas.repository.Constants.PURPOSE_ENTITY_TYPE;
import static org.apache.ranger.plugin.model.RangerPolicy.MASK_TYPE_NONE;
import static org.apache.ranger.plugin.model.RangerPolicy.POLICY_TYPE_ACCESS;
import static org.apache.ranger.plugin.model.RangerPolicy.POLICY_TYPE_DATAMASK;

public class PurposeServiceHelper {
    private static final Logger LOG = LoggerFactory.getLogger(PurposeServiceHelper.class);

    protected static void validatePurpose(AtlasGraph graph, PurposeContext context) throws AtlasBaseException {
        AtlasEntity purposeEntity = context.getPurposeExtInfo().getEntity();
        List<String> tags = getTags(purposeEntity);

        if (CollectionUtils.isEmpty(tags)) {
            throw new AtlasBaseException(BAD_REQUEST, "Please provide purposeClassifications for Purpose");
        }

        validateUniquenessByName(graph, getName(purposeEntity), PURPOSE_ENTITY_TYPE);
        validateUniquenessByTags(graph, tags, PURPOSE_ENTITY_TYPE);
    }

    protected static void validatePurposePolicy(PurposeContext context) throws AtlasBaseException {
        validatePurposePolicyRequest(context);
        verifyUniqueNameForPurposePolicy(context);
    }

    private static void validatePurposePolicyRequest(PurposeContext context) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("validatePurposePolicyRequest");
        AtlasEntity purposePolicy = context.getPurposePolicy();

        try {
            if (context.isCreateNewPurposePolicy()) {
                if (!AtlasEntity.Status.ACTIVE.equals(context.getPurpose().getStatus())) {
                    throw new AtlasBaseException(OPERATION_NOT_SUPPORTED, "Purpose not Active");
                }

                if (isDataPolicy(purposePolicy) && !purposePolicy.hasAttribute(ATTR_DATA_MASKING)) {
                    purposePolicy.setAttribute(ATTR_DATA_MASKING, RANGER_MASK_NONE);
                }
            } else {
                if (!getPolicyType(purposePolicy).equals(getPolicyType(context.getExistingPurposePolicy()))) {
                    throw new AtlasBaseException(OPERATION_NOT_SUPPORTED, "Policy type change not Allowed");
                }

                if (!getPolicyCategory(purposePolicy).equals(getPolicyCategory(context.getExistingPurposePolicy()))) {
                    throw new AtlasBaseException(OPERATION_NOT_SUPPORTED, "Policy category change not Allowed");
                }

                AtlasObjectId existingPersona = (AtlasObjectId) context.getExistingPurposePolicy().getRelationshipAttribute(REL_ATTR_ACCESS_CONTROL);
                String existingPersonaGuid = existingPersona.getGuid();
                if (!context.getPurpose().getGuid().equals(existingPersonaGuid)) {
                    throw new AtlasBaseException(OPERATION_NOT_SUPPORTED, "Policy parent (accesscontrol) change is not Allowed");
                }

                if (!AtlasEntity.Status.ACTIVE.equals(context.getExistingPurposePolicy().getStatus())) {
                    throw new AtlasBaseException(OPERATION_NOT_SUPPORTED, "Policy is not Active");
                }
            }

            List<String> actions = getActions(purposePolicy);

            if (CollectionUtils.isEmpty(actions)) {
                if (context.isCreateNewPurposePolicy() || purposePolicy.hasAttribute(ATTR_POLICY_ACTIONS)) {
                    throw new AtlasBaseException(BAD_REQUEST, "Please provide actions for policy");
                }
            }

            validatePurposePolicyActions(actions);

            if (CollectionUtils.isEmpty(getPolicyUsers(purposePolicy)) && CollectionUtils.isEmpty(getPolicyGroups(purposePolicy))
                    && !getIsAllUsers(purposePolicy)) {

                throw new AtlasBaseException(BAD_REQUEST, "Please provide users/groups OR select All users for policy");
            }
        } finally {
            RequestContext.get().endMetricRecord(metricRecorder);
        }
    }

    private static void verifyUniqueNameForPurposePolicy(PurposeContext context) throws AtlasBaseException {

        if (!context.isCreateNewPurposePolicy() && !getName(context.getExistingPurposePolicy()).equals(getName(context.getPurpose()))) {
            return;
        }
        List<String> policyNames = new ArrayList<>();
        String newPolicyName = getName(context.getPurposePolicy());

        List<AtlasEntity> policies = getPolicies(context.getPurposeExtInfo());

        if (CollectionUtils.isNotEmpty(policies)) {
            if (context.isCreateNewPurposePolicy()) {
                policies = policies.stream()
                        .filter(x -> !x.getGuid().equals(context.getPurposePolicy().getGuid()))
                        .collect(Collectors.toList());
            }
        }

        policies.forEach(x -> policyNames.add(getName(x)));

        if (policyNames.contains(newPolicyName)) {
            throw new AtlasBaseException(POLICY_ALREADY_EXISTS, newPolicyName);
        }
    }

    private static void validatePurposePolicyActions(List<String> actions) throws AtlasBaseException {
        Set<String> actionsSet = new HashSet<>(actions);
        actionsSet.removeAll(POLICY_ACTIONS);

        if (actionsSet.size() > 0) {
            throw new AtlasBaseException(BAD_REQUEST, "Please provide valid action for policy");
        }
    }

    protected static List<RangerPolicy> purposePolicyToRangerPolicy(PurposeContext context) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metricRecorder = RequestContext.get().startMetricRecord("purposePolicyToRangerPolicy");

        List<RangerPolicy> ret = new ArrayList<>();
        RangerPolicy rangerAccessPolicy, rangerMaskPolicy;

        AtlasEntity purpose = context.getPurpose();

        List<String> tags = getTags(purpose);
        try {
            if (CollectionUtils.isEmpty(tags)) {
                throw new AtlasBaseException("Tags list is empty");
            }

            rangerAccessPolicy = getRangerPolicy(context, POLICY_TYPE_ACCESS);
            rangerMaskPolicy = getRangerPolicy(context, POLICY_TYPE_DATAMASK);

            Map<String, RangerPolicy.RangerPolicyResource> resources = new HashMap<>();
            resources.put(RESOURCE_TAG, new RangerPolicy.RangerPolicyResource(tags, false, false));

            rangerAccessPolicy.setResources(resources);
            rangerMaskPolicy.setResources(resources);

            policyToRangerPolicy(context, rangerAccessPolicy, rangerMaskPolicy);

            ret.add(rangerAccessPolicy);
            ret.add(rangerMaskPolicy);
        } finally {
            RequestContext.get().endMetricRecord(metricRecorder);
        }
        return ret;
    }

    private static RangerPolicy getRangerPolicy(PurposeContext context, int policyType){
        RangerPolicy rangerPolicy = new RangerPolicy();
        AtlasEntity purpose = context.getPurpose();

        rangerPolicy.setPolicyLabels(Arrays.asList(getPurposeLabel(purpose.getGuid()), "type:purpose"));

        rangerPolicy.setPolicyType(policyType);
        rangerPolicy.setServiceType("tag"); //TODO: disable & check
        rangerPolicy.setService("default_atlan"); //TODO: read from property config

        return rangerPolicy;
    }

    private static void policyToRangerPolicy(PurposeContext context, RangerPolicy rangerAccessPolicy, RangerPolicy rangerMaskPolicy) {
        rangerAccessPolicy.setName("purpose-tag-" + UUID.randomUUID());

        for (AtlasEntity policy : getPolicies(context.getPurposeExtInfo())) {
            if (context.isDeletePurposePolicy() && policy.getGuid().equals(context.getPurposePolicy().getGuid())) {
                continue;
            }

            List<String> actions = getActions(policy);
            List<RangerPolicy.RangerPolicyItemAccess> accesses = new ArrayList<>();

            if (isDataPolicy(policy)) {
                for (String action : actions) {
                    accesses.add(new RangerPolicy.RangerPolicyItemAccess(formatAccessType("heka", action)));
                }

                if (isDataMaskPolicy(policy)) {
                    rangerMaskPolicy.setName("purpose-tag-mask-" + UUID.randomUUID());
                    String maskType = getDataPolicyMaskType(policy);
                    RangerPolicy.RangerPolicyItemDataMaskInfo maskInfo = new RangerPolicy.RangerPolicyItemDataMaskInfo(formatMaskType(maskType), null, null);
                    setPolicyItem(policy, rangerMaskPolicy, accesses, maskInfo);
                    rangerMaskPolicy.getPolicyLabels().add(getPurposePolicyLabel(policy.getGuid()));

                } else {
                    setPolicyItem(policy, rangerAccessPolicy, accesses, null);
                    rangerAccessPolicy.getPolicyLabels().add(getPurposePolicyLabel(policy.getGuid()));
                }
            } else {
                for (String action : actions) {
                    //TODO: validate actions
                    if (action.equals(LINK_ASSET_ACTION)) {
                        accesses.add(new RangerPolicy.RangerPolicyItemAccess(formatAccessType(ACCESS_ADD_REL)));
                        accesses.add(new RangerPolicy.RangerPolicyItemAccess(formatAccessType(ACCESS_UPDATE_REL)));
                        accesses.add(new RangerPolicy.RangerPolicyItemAccess(formatAccessType(ACCESS_REMOVE_REL)));
                    } else {
                        accesses.add(new RangerPolicy.RangerPolicyItemAccess(formatAccessType(action)));
                    }
                }
                setPolicyItem(policy, rangerAccessPolicy, accesses, null);
                rangerAccessPolicy.getPolicyLabels().add(getPurposePolicyLabel(policy.getGuid()));
            }
        }
    }

    private static void setPolicyItem(AtlasEntity purposePolicy, RangerPolicy rangerPolicy,
                               List<RangerPolicy.RangerPolicyItemAccess> accesses, RangerPolicy.RangerPolicyItemDataMaskInfo maskInfo) {

        List<String> users = getPolicyUsers(purposePolicy);
        List<String> groups = getPolicyGroups(purposePolicy);
        if (getIsAllUsers(purposePolicy)) {
            users = null;
            groups = Collections.singletonList("public");
        }

        if (maskInfo != null) {
            RangerPolicy.RangerDataMaskPolicyItem policyItem = new RangerPolicy.RangerDataMaskPolicyItem(accesses, maskInfo, users, groups, null, null, false);
            rangerPolicy.getDataMaskPolicyItems().add(policyItem);

        } else {
            RangerPolicy.RangerPolicyItem policyItem = new RangerPolicy.RangerPolicyItem(accesses, users, groups, null, null, false);

            if (getIsAllow(purposePolicy)) {
                rangerPolicy.getPolicyItems().addAll(Collections.singletonList(policyItem));
            } else {
                rangerPolicy.getDenyPolicyItems().addAll(Collections.singletonList(policyItem));
            }
        }
    }
}
