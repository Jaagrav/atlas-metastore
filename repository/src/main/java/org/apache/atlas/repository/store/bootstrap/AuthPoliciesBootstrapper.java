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

package org.apache.atlas.repository.store.bootstrap;

import org.apache.atlas.ApplicationProperties;
import org.apache.atlas.AtlasException;
import org.apache.atlas.RequestContext;
import org.apache.atlas.listener.ActiveStateChangeHandler;
import org.apache.atlas.model.instance.AtlasEntity;
import org.apache.atlas.model.instance.AtlasEntity.AtlasEntitiesWithExtInfo;
import org.apache.atlas.repository.graphdb.AtlasGraph;
import org.apache.atlas.repository.store.graph.AtlasEntityStore;
import org.apache.atlas.repository.store.graph.v2.AtlasEntityStream;
import org.apache.atlas.repository.store.graph.v2.EntityStream;
import org.apache.atlas.repository.util.AccessControlUtils;
import org.apache.atlas.service.Service;
import org.apache.atlas.type.AtlasType;
import org.apache.atlas.type.AtlasTypeRegistry;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.apache.atlas.repository.Constants.KEYCLOAK_ROLE_ADMIN;

@Component
@Order(9)
public class AuthPoliciesBootstrapper implements ActiveStateChangeHandler, Service {
    public static final Logger LOG = LoggerFactory.getLogger(AuthPoliciesBootstrapper.class);

    private final AtlasGraph graph;
    private final AtlasTypeRegistry typeRegistry;
    private final AtlasEntityStore entityStore;

    private static File POLICIES_DIR = null;

    @Inject
    public AuthPoliciesBootstrapper(AtlasGraph graph,
                                    AtlasEntityStore entityStore,
                                    AtlasTypeRegistry typeRegistry) {
        this.graph = graph;
        this.entityStore = entityStore;
        this.typeRegistry = typeRegistry;

        if (POLICIES_DIR == null) {
            String atlasHomeDir = System.getProperty("atlas.home");
            String topPoliciesDir = (StringUtils.isEmpty(atlasHomeDir) ? "." : atlasHomeDir) + File.separator + "policies";
            POLICIES_DIR = new File(topPoliciesDir);
        }
    }

    public List<AtlasEntity> getAdminPolicies() throws IOException {
        List<AtlasEntity> ret = new ArrayList<>();
        List<File> policyFiles = getAllPolicyFiles(POLICIES_DIR);

        for (File policyFile : policyFiles) {
            AtlasEntitiesWithExtInfo policies = getPolicies(policyFile);

            for (AtlasEntity policy : policies.getEntities()) {
                List<String> roles = AccessControlUtils.getPolicyRoles(policy);

                if (roles.contains(KEYCLOAK_ROLE_ADMIN)) {
                    ret.add(policy);
                }
            }
        }
        return ret;
    }

    private void startInternal() {
        try {
            String authorizer = ApplicationProperties.get().getString("atlas.authorizer.impl", "");

            if ("atlas".equals(authorizer)) {
                loadBootstrapAuthPolicies();
            } else {
                LOG.info("AuthPoliciesBootstrapper: startInternal: Skipping as not needed");
            }
        } catch (Exception e) {
            LOG.error("Failed to init after becoming active", e);
        } finally {
            RequestContext.clear();
        }
    }

    private void loadBootstrapAuthPolicies() {
        LOG.info("==> AuthPoliciesBootstrapper.loadBootstrapAuthPolicies()");

        RequestContext.get().setPoliciesBootstrappingInProgress(true);

        List<File> policyFiles = getAllPolicyFiles(POLICIES_DIR);

        for (File policyFile : policyFiles) {
            loadPoliciesInFile(policyFile);
        }

        LOG.info("<== AuthPoliciesBootstrapper.loadBootstrapAuthPolicies()");
    }

    private List<File> getAllPolicyFiles(File policiesDir) {
        List<File> files = new ArrayList<>(0);

        String policiesDirName = policiesDir.getName();
        File[] policyFiles = policiesDir.exists() ? policiesDir.listFiles() : null;

        if (ArrayUtils.isNotEmpty(policyFiles)) {
            for (File item : policyFiles) {

                if (!item.isFile()) {
                    files.addAll(getAllPolicyFiles(item));
                } else {
                    files.add(item);
                }
            }
        } else {
            LOG.warn("No policies for Bootstrapping in directory {}..", policiesDirName);
        }

        return files;
    }

    private void loadPoliciesInFile (File policyFile) {
        LOG.info("==> AuthPoliciesBootstrapper.loadPoliciesInFile({})", policyFile);

        try {
            AtlasEntitiesWithExtInfo policies = getPolicies(policyFile);

            if (policies == null || CollectionUtils.isEmpty(policies.getEntities())) {
                LOG.info("No policy in file {}", policyFile.getAbsolutePath());

                return;
            }

            EntityStream entityStream = new AtlasEntityStream(policies);

            entityStore.createOrUpdate(entityStream, false);

        } catch (Throwable t) {
            LOG.error("error while registering policies in file {}", policyFile.getAbsolutePath(), t);
        }


        LOG.info("<== AuthPoliciesBootstrapper.loadPoliciesInFile({})", policyFile);
    }

    private AtlasEntitiesWithExtInfo getPolicies(File policyFile) throws IOException {
        String jsonStr  = new String(Files.readAllBytes(policyFile.toPath()), StandardCharsets.UTF_8);
        return AtlasType.fromJson(jsonStr, AtlasEntitiesWithExtInfo.class);
    }

    @Override
    public void instanceIsActive() throws AtlasException {
        startInternal();
    }

    @Override
    public void instanceIsPassive() throws AtlasException {

    }

    @Override
    public int getHandlerOrder() {
        return HandlerOrder.AUTH_POLICIES_INITIALIZER.getOrder();
    }

    //@Override
    public void start() throws AtlasException {
        startInternal();
    }

    //@Override
    public void stop() throws AtlasException {

    }
}
