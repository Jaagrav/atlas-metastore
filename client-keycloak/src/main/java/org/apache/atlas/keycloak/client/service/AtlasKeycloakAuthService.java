package org.apache.atlas.keycloak.client.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import okhttp3.logging.HttpLoggingInterceptor;
import org.apache.atlas.exception.AtlasBaseException;
import org.apache.atlas.keycloak.client.RetrofitKeycloakClient;
import org.apache.atlas.keycloak.client.config.KeycloakConfig;
import org.jetbrains.annotations.NotNull;
import org.keycloak.representations.AccessTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import static org.apache.atlas.AtlasErrorCode.BAD_REQUEST;

public final class AtlasKeycloakAuthService {

    public final static Logger LOG = LoggerFactory.getLogger(AtlasKeycloakAuthService.class);

    private final static String GRANT_TYPE = "grant_type";
    private static final String CLIENT_ID = "client_id";
    private static final String CLIENT_SECRET = "client_secret";
    private static final int EXPIRY_OFFSET_SEC = 600;
    private static final int TIMEOUT_IN_SECS = 60;

    private final RetrofitKeycloakClient retrofit;
    private final KeycloakConfig keycloakConfig;
    private AccessTokenResponse currentAccessToken;
    private long expirationTime = -1;

    public AtlasKeycloakAuthService(KeycloakConfig keycloakConfig) {
        this.keycloakConfig = keycloakConfig;
        this.retrofit = new Retrofit.Builder().client(getOkHttpClient())
                .baseUrl(this.keycloakConfig.getAuthServerUrl())
                .addConverterFactory(JacksonConverterFactory.create(new ObjectMapper())).build()
                .create(RetrofitKeycloakClient.class);
    }

    @NotNull
    private OkHttpClient getOkHttpClient() {
        HttpLoggingInterceptor interceptor = new HttpLoggingInterceptor();
        interceptor.setLevel(HttpLoggingInterceptor.Level.BODY);
        return new OkHttpClient.Builder()
                .addInterceptor(interceptor)
                .addInterceptor(responseLoggingInterceptor)
                .connectTimeout(TIMEOUT_IN_SECS, TimeUnit.SECONDS)
                .callTimeout(TIMEOUT_IN_SECS, TimeUnit.SECONDS)
                .writeTimeout(TIMEOUT_IN_SECS, TimeUnit.SECONDS)
                .readTimeout(TIMEOUT_IN_SECS, TimeUnit.SECONDS)
                .build();
    }

    Interceptor responseLoggingInterceptor = chain -> {
        Request request = chain.request();
        okhttp3.Response response = chain.proceed(request);
        LOG.info("Keycloak: Auth Request for url {} Status: {}", request.url(), response.code());
        return response;
    };

    public String getAuthToken() {
        if (!isTokenExpired()) {
            return currentAccessToken.getToken();
        }
        synchronized (this) {
            if (isTokenExpired()) {
                try {
                    retrofit2.Response<AccessTokenResponse> resp = this.retrofit.grantToken(this.keycloakConfig.getRealmId(), getTokenRequest()).execute();
                    if (resp.isSuccessful()) {
                        currentAccessToken = resp.body();
                        expirationTime = currentTime() + currentAccessToken.getExpiresIn() - EXPIRY_OFFSET_SEC;
                        LOG.info("Keycloak: Auth token fetched with expiry:{} sec", expirationTime);
                    } else {
                        throw new AtlasBaseException(BAD_REQUEST, resp.errorBody().string());
                    }
                } catch (Exception e) {
                    LOG.error("Keycloak: Error while fetching access token for keycloak client.", e);
                    throw new RuntimeException(e);
                }
            }
        }
        return currentAccessToken.getToken();
    }

    public boolean isTokenExpired() {
        synchronized (this) {
            if (Objects.isNull(currentAccessToken)) {
                return true;
            }
            return currentTime() >= expirationTime;
        }
    }

    private RequestBody getTokenRequest() {
        return new FormBody.Builder().addEncoded(CLIENT_ID, this.keycloakConfig.getClientId()).addEncoded(CLIENT_SECRET, this.keycloakConfig.getClientSecret()).addEncoded(GRANT_TYPE, this.keycloakConfig.getGrantType()).build();
    }

    private long currentTime() {
        return OffsetDateTime.now().toEpochSecond();
    }

}
