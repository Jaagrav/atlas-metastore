package org.apache.atlas.tasks;

import org.apache.atlas.AtlasErrorCode;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.model.tasks.AtlasTask;
import org.apache.atlas.model.tasks.TaskSearchParams;
import org.apache.atlas.model.tasks.TaskSearchResult;
import org.apache.atlas.repository.Constants;
import org.apache.atlas.repository.graphdb.AtlasGraph;
import org.apache.atlas.repository.graphdb.AtlasIndexQuery;
import org.apache.atlas.repository.graphdb.AtlasVertex;
import org.apache.atlas.repository.graphdb.DirectIndexQueryResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.apache.atlas.repository.store.graph.v2.AtlasGraphUtilsV2.setEncodedProperty;
import static org.apache.atlas.tasks.TaskRegistry.toAtlasTask;

@Component
public class AtlasTaskService implements TaskService {
    private static final Logger LOG = LoggerFactory.getLogger(AtlasTaskService.class);

    private final AtlasGraph graph;

    private final List<String> retryAllowedStatuses;

    @Inject
    public AtlasTaskService(AtlasGraph graph) {
        this.graph = graph;
        retryAllowedStatuses = new ArrayList<>();
        retryAllowedStatuses.add(AtlasTask.Status.COMPLETE.toString());
        retryAllowedStatuses.add(AtlasTask.Status.FAILED.toString());
        // Since classification vertex is deleted after the task gets deleted, no need to retry the DELETED task
    }

    @Override
    public TaskSearchResult getTasks(TaskSearchParams searchParams) throws AtlasBaseException {
        TaskSearchResult ret = new TaskSearchResult();
        List<AtlasTask> tasks = new ArrayList<>();
        AtlasIndexQuery indexQuery = null;
        DirectIndexQueryResult indexQueryResult;

        try {
            indexQuery = searchTask(searchParams);
            indexQueryResult = indexQuery.vertices(searchParams);

            if (indexQueryResult != null) {
                Iterator<AtlasIndexQuery.Result> iterator = indexQueryResult.getIterator();

                while (iterator.hasNext()) {
                    AtlasVertex vertex = iterator.next().getVertex();

                    if (vertex != null) {
                        tasks.add(toAtlasTask(vertex));
                    } else {
                        LOG.warn("Null vertex while fetching tasks");
                    }

                }

                ret.setTasks(tasks);
                ret.setApproximateCount(indexQuery.vertexTotals());
                ret.setAggregations(indexQueryResult.getAggregationMap());
            }
        } catch (AtlasBaseException e) {
            LOG.error("Failed to fetch tasks: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            e.printStackTrace();
            throw new AtlasBaseException(AtlasErrorCode.RUNTIME_EXCEPTION, e);
        }

        return ret;
    }

    @Override
    public void retryTask(String taskGuid) throws AtlasBaseException {
        DirectIndexQueryResult indexQueryResult = searchTask(taskGuid);

        Iterator<AtlasIndexQuery.Result> iterator = indexQueryResult.getIterator();

        if (iterator.hasNext()) {
            AtlasVertex atlasVertex = iterator.next().getVertex();

            String status = atlasVertex.getProperty(Constants.TASK_STATUS, String.class);

            // Retrial ability of the task is not limited to FAILED ones due to testing/debugging
            if (! retryAllowedStatuses.contains(status)) {
                throw new AtlasBaseException(AtlasErrorCode.TASK_STATUS_NOT_APPROPRIATE, taskGuid, status);
            }

            setEncodedProperty(atlasVertex, Constants.TASK_STATUS, AtlasTask.Status.PENDING);
            int attemptCount = atlasVertex.getProperty(Constants.TASK_ATTEMPT_COUNT, Integer.class);
            setEncodedProperty(atlasVertex, Constants.TASK_ATTEMPT_COUNT, attemptCount+1);
            graph.commit();
        } else {
            throw new AtlasBaseException(AtlasErrorCode.TASK_NOT_FOUND, taskGuid);
        }
    }

    private AtlasIndexQuery searchTask(TaskSearchParams searchParams) {
        return graph.elasticsearchQuery(Constants.VERTEX_INDEX, searchParams);
    }

    private DirectIndexQueryResult searchTask(String taskGuid) throws AtlasBaseException {
        TaskSearchParams searchParams = new TaskSearchParams();
        searchParams.setDsl(searchParams.getDSLGuid(taskGuid));
        AtlasIndexQuery indexQuery = graph.elasticsearchQuery(Constants.VERTEX_INDEX, searchParams);
        return indexQuery.vertices(searchParams);
    }
}
