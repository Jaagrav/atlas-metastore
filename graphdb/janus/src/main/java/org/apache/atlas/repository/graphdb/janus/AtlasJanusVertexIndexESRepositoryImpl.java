package org.apache.atlas.repository.graphdb.janus;

import org.apache.atlas.AtlasErrorCode;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.http.HttpEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.action.update.UpdateResponse;
import org.elasticsearch.client.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import java.io.IOException;
import java.util.Collections;
import java.util.Objects;

import static org.apache.atlas.repository.Constants.INDEX_PREFIX;
import static org.apache.atlas.repository.Constants.VERTEX_INDEX;
import static org.apache.atlas.repository.graphdb.janus.AtlasElasticsearchDatabase.getClient;
import static org.apache.atlas.repository.graphdb.janus.AtlasElasticsearchDatabase.getLowLevelClient;

@Repository
public class AtlasJanusVertexIndexESRepositoryImpl implements AtlasJanusVertexIndexRepository {

    private static final Logger LOG = LoggerFactory.getLogger(AtlasJanusVertexIndexESRepositoryImpl.class);
    private final RestHighLevelClient elasticSearchClient = getClient();
    private final RestClient elasticSearchLowLevelClient = getLowLevelClient();
    private static final int MAX_RETRIES = 3;
    private static final int RETRY_TIME_IN_MILLIS = 1000;
    private static final String INDEX = INDEX_PREFIX + VERTEX_INDEX;

    // TODO: can async ES call
    @Override
    public UpdateResponse updateDoc(UpdateRequest request, RequestOptions options) throws AtlasBaseException {
        int count = 0;
        while(true) {
            try {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Updating entity in ES with req {}", request.toString());
                }
                return elasticSearchClient.update(request, options);
            } catch (IOException e) {
                LOG.warn(String.format("Exception while trying to create nested relationship for req %s. Retrying",
                        request.toString()), e);
                LOG.info("Retrying with delay of {} ms ", RETRY_TIME_IN_MILLIS);
                try {
                    Thread.sleep(RETRY_TIME_IN_MILLIS);
                } catch (InterruptedException ex) {
                    LOG.warn("Retry interrupted during edge creation ");
                    throw new AtlasBaseException(AtlasErrorCode.RUNTIME_EXCEPTION, ex);
                }
                if (++count == MAX_RETRIES) {
                    if (++count == MAX_RETRIES) {
                        LOG.error("Failed to execute direct update on ES {}", e.getMessage());
                        throw new AtlasBaseException(AtlasErrorCode.ES_DIRECT_UPDATE_FAILED, e.getMessage());
                    }
                }
            }
        }
    }

    @Override
    public Response performRawRequest(String queryJson, String docId) throws AtlasBaseException {
        Objects.requireNonNull(queryJson, "query");
        int count = 0;
        while(true) {
            final String endPoint = "/" + INDEX + "/_update" + "/" + docId + "?retry_on_conflict=5";
            try {
                Request request = new Request(
                        "POST",
                        endPoint);
                request.addParameters(Collections.emptyMap());
                HttpEntity entity = new StringEntity(queryJson, ContentType.APPLICATION_JSON);
                request.setEntity(entity);
                return elasticSearchLowLevelClient.performRequest(request);
            } catch (IOException e) {
                LOG.error(ExceptionUtils.getStackTrace(e));
                LOG.info("Retrying with delay of {} ms ", RETRY_TIME_IN_MILLIS);
                try {
                    Thread.sleep(RETRY_TIME_IN_MILLIS);
                } catch (InterruptedException ex) {
                    LOG.warn("Retry interrupted during ES relationship creation/deletion");
                    throw new AtlasBaseException(AtlasErrorCode.RUNTIME_EXCEPTION, ex);
                }
                if (++count == MAX_RETRIES) {
                    LOG.error("Failed to execute direct update on ES {}", e.getMessage());
                    throw new AtlasBaseException(AtlasErrorCode.ES_DIRECT_UPDATE_FAILED, e.getMessage());
                }
            }
        }
    }
}