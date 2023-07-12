package org.apache.atlas.tasks;

import org.apache.atlas.AtlasErrorCode;
import org.apache.atlas.DeleteType;
import org.apache.atlas.RequestContext;
import org.apache.atlas.annotation.GraphTransaction;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.model.tasks.AtlasTask;
import org.apache.atlas.model.tasks.TaskSearchParams;
import org.apache.atlas.model.tasks.TaskSearchResult;
import org.apache.atlas.repository.Constants;
import org.apache.atlas.repository.graphdb.*;
import org.apache.atlas.utils.AtlasJson;
import org.apache.atlas.utils.AtlasPerfMetrics;
import org.apache.commons.collections.CollectionUtils;
import org.reflections8.Reflections;
import org.reflections8.scanners.SubTypesScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import java.lang.reflect.Field;
import java.util.*;

import static org.apache.atlas.repository.Constants.TASK_GUID;
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
    public TaskSearchResult getTasksByCondition(int from, int size, List<Map<String,Object>> mustConditions, List<Map<String,Object>> shouldConditions,
                                                List<Map<String,Object>> mustNotConditions) throws AtlasBaseException {
        Map<String, Object> dsl = getMap("from", from);
        dsl.put("size", size);
        Map<String, Map<String, Object>> boolCondition = Collections.singletonMap("bool", new HashMap<>());
        Map<String, Object> shouldQuery = getMap("bool", getMap("should", shouldConditions));
        mustConditions.add(shouldQuery);
        boolCondition.get("bool").put("must", mustConditions);
        boolCondition.get("bool").put("must_not", mustNotConditions);

        dsl.put("query", boolCondition);
        TaskSearchParams taskSearchParams = new TaskSearchParams();
        taskSearchParams.setDsl(dsl);
        TaskSearchResult tasks = getTasks(taskSearchParams);
        return tasks;
    }

    private Map<String, Object> getMap(String key, Object value) {
        Map<String, Object> map = new HashMap<>();
        map.put(key, value);
        return map;
    }
    @Override
    public void retryTask(String taskGuid) throws AtlasBaseException {
        TaskSearchParams taskSearchParams = getMatchQuery(taskGuid);
        AtlasIndexQuery atlasIndexQuery = searchTask(taskSearchParams);
        DirectIndexQueryResult indexQueryResult = atlasIndexQuery.vertices(taskSearchParams);

        AtlasVertex atlasVertex = getTaskVertex(indexQueryResult.getIterator(), taskGuid);

        String status = atlasVertex.getProperty(Constants.TASK_STATUS, String.class);

        // Retrial ability of the task is not limited to FAILED ones due to testing/debugging
        if (! retryAllowedStatuses.contains(status)) {
            throw new AtlasBaseException(AtlasErrorCode.TASK_STATUS_NOT_APPROPRIATE, taskGuid, status);
        }

        setEncodedProperty(atlasVertex, Constants.TASK_STATUS, AtlasTask.Status.PENDING);
        int attemptCount = atlasVertex.getProperty(Constants.TASK_ATTEMPT_COUNT, Integer.class);
        setEncodedProperty(atlasVertex, Constants.TASK_ATTEMPT_COUNT, attemptCount+1);
        graph.commit();
    }

    @Override
    @GraphTransaction
    public List<AtlasTask> createAtlasTasks(List<AtlasTask> tasks) throws AtlasBaseException {
        AtlasPerfMetrics.MetricRecorder metric = RequestContext.get().startMetricRecord("createAtlasTasks");
        List<String> supportedTypes = new ArrayList<>();
        // Get all the supported task type dynamically
        Reflections reflections = new Reflections("org.apache.atlas.repository.store.graph.v2.tasks", new SubTypesScanner(false));
        Set<Class<? extends TaskFactory>> classes = reflections.getSubTypesOf(TaskFactory.class);
        for (Class<?> clazz : classes) {
            List<Class<?>> interfaces = Arrays.asList(clazz.getInterfaces());
            if (interfaces.contains(TaskFactory.class)) {
                try {
                    Field field = clazz.getField("supportedTypes");
                    List<String> supportedTaskTypes = (List<String>) field.get(null);
                    supportedTypes.addAll(supportedTaskTypes);
                } catch (NoSuchFieldException | IllegalAccessException e) {
                    LOG.error("Error occurred while accessing field: ", e);
                    throw new AtlasBaseException("Error occurred while accessing field", e);
                }
            }
        }
        List<AtlasTask> createdTasks = new ArrayList<>();

        if (CollectionUtils.isNotEmpty(tasks)) {
            for (AtlasTask task : tasks) {
                String taskType = task.getType();
                if (!supportedTypes.contains(taskType)) {
                    LOG.error("Task type {} is not supported", taskType);
                    continue;
                }
                task.setUpdatedTime(new Date());
                task.setCreatedTime(new Date());
                task.setStatusPending();
                task.setAttemptCount(0);
                task.setGuid(UUID.randomUUID().toString());
                task.setCreatedBy(RequestContext.getCurrentUser());

                createTaskVertex(task);
                createdTasks.add(task);
            }
        }

        graph.commit();
        RequestContext.get().endMetricRecord(metric);
        return createdTasks;
    }

    @Override
    public List<AtlasTask> deleteAtlasTasks(List<AtlasTask> tasks) {
        AtlasPerfMetrics.MetricRecorder metric = RequestContext.get().startMetricRecord("deleteAtlasTasks");
        List<AtlasTask> deletedTasks = new ArrayList<>();
        if (CollectionUtils.isNotEmpty(tasks)) {
            for (AtlasTask task : tasks) {
                String taskGuid = task.getGuid();
                try {
                    deleteTask(taskGuid);

                    deletedTasks.add(task);
                } catch (AtlasBaseException e) {
                    LOG.error("Failed to delete task {}", taskGuid);
                }
            }
        }

        graph.commit();
        RequestContext.get().endMetricRecord(metric);
        return deletedTasks;
    }

    private void deleteTask(String taskGuid) throws AtlasBaseException {
        DeleteType deleteType = RequestContext.get().getDeleteType();
        if (deleteType == DeleteType.SOFT || deleteType == DeleteType.DEFAULT) {
            softDelete(taskGuid);
        } else if (deleteType == DeleteType.HARD) {
            hardDelete(taskGuid);
        }
    }

    @GraphTransaction
    public AtlasVertex createTaskVertex(AtlasTask task) {
        AtlasVertex ret = graph.addVertex();

        setEncodedProperty(ret, Constants.TASK_GUID, task.getGuid());
        setEncodedProperty(ret, Constants.TASK_TYPE_PROPERTY_KEY, Constants.TASK_TYPE_NAME);
        setEncodedProperty(ret, Constants.TASK_STATUS, task.getStatus().toString());
        setEncodedProperty(ret, Constants.TASK_TYPE, task.getType());
        setEncodedProperty(ret, Constants.TASK_CREATED_BY, task.getCreatedBy());
        setEncodedProperty(ret, Constants.TASK_CREATED_TIME, task.getCreatedTime());
        setEncodedProperty(ret, Constants.TASK_UPDATED_TIME, task.getUpdatedTime());
        if (task.getClassificationId() != null) {
            setEncodedProperty(ret, Constants.TASK_CLASSIFICATION_ID, task.getClassificationId());
        }

        if(task.getEntityGuid() != null) {
            setEncodedProperty(ret, Constants.TASK_ENTITY_GUID, task.getEntityGuid());
        }

        if (task.getStartTime() != null) {
            setEncodedProperty(ret, Constants.TASK_START_TIME, task.getStartTime().getTime());
        }

        if (task.getEndTime() != null) {
            setEncodedProperty(ret, Constants.TASK_END_TIME, task.getEndTime().getTime());
        }

        setEncodedProperty(ret, Constants.TASK_PARAMETERS, AtlasJson.toJson(task.getParameters()));
        setEncodedProperty(ret, Constants.TASK_ATTEMPT_COUNT, task.getAttemptCount());
        setEncodedProperty(ret, Constants.TASK_ERROR_MESSAGE, task.getErrorMessage());

        LOG.info("Creating task vertex: {}: {}, {}: {}, {}: {} ",
                Constants.TASK_TYPE, task.getType(),
                Constants.TASK_PARAMETERS, AtlasJson.toJson(task.getParameters()),
                TASK_GUID, task.getGuid());

        return ret;
    }

    @GraphTransaction
    @Override
    public void hardDelete(String guid) throws AtlasBaseException {
        try {
            AtlasGraphQuery query = graph.query()
                    .has(Constants.TASK_TYPE_PROPERTY_KEY, Constants.TASK_TYPE_NAME)
                    .has(TASK_GUID, guid);

            Iterator<AtlasVertex> results = query.vertices().iterator();

            if (results.hasNext()) {
                graph.removeVertex(results.next());
            }
        } catch (Exception exception) {
            LOG.error("Error: deletingByGuid: {}", guid);

            throw new AtlasBaseException(exception);
        } finally {
            graph.commit();
        }
    }

    @GraphTransaction
    @Override
    public void softDelete(String guid) throws AtlasBaseException{
        try {
            AtlasGraphQuery query = graph.query()
                    .has(Constants.TASK_TYPE_PROPERTY_KEY, Constants.TASK_TYPE_NAME)
                    .has(TASK_GUID, guid);

            Iterator<AtlasVertex> results = query.vertices().iterator();

            if (results.hasNext()) {
                AtlasVertex taskVertex = results.next();

                setEncodedProperty(taskVertex, Constants.TASK_STATUS, AtlasTask.Status.DELETED);
                setEncodedProperty(taskVertex, Constants.TASK_UPDATED_TIME, System.currentTimeMillis());
            }
        }
        catch (Exception exception) {
            LOG.error("Error: on soft delete: {}", guid);

            throw new AtlasBaseException(exception);
        }
    }

    private AtlasVertex getTaskVertex(Iterator<AtlasIndexQuery.Result> iterator, String taskGuid) throws AtlasBaseException {
        while(iterator.hasNext()) {
            AtlasVertex atlasVertex = iterator.next().getVertex();
            if (atlasVertex.getProperty(Constants.TASK_GUID, String.class).equals(taskGuid)) {
                return atlasVertex;
            }
        }
        throw new AtlasBaseException(AtlasErrorCode.TASK_NOT_FOUND, taskGuid);
    }

    private TaskSearchParams getMatchQuery(String guid) {
        TaskSearchParams params = new TaskSearchParams();
        params.setDsl(mapOf("query", mapOf("match", mapOf(TASK_GUID, guid))));
        return params;
    }

    private Map<String, Object> mapOf(String key, Object value) {
        Map<String, Object> map = new HashMap<>();
        map.put(key, value);

        return map;
    }

    private AtlasIndexQuery searchTask(TaskSearchParams searchParams) throws AtlasBaseException {
        return graph.elasticsearchQuery(Constants.VERTEX_INDEX, searchParams);
    }
}
