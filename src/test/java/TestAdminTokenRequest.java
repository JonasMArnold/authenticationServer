import com.example.auth.dto.BearerTokenResponseDto;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class TestAdminTokenRequest {

    @Test
    public void testOAuth2TokenRequest() {
        // Define your client credentials
        String clientId = "admin-api";
        String clientSecret = "Trqp1P2WxREhLL3QHFBtj4Crkv90yPcX1PekKduA";

        // Create a WebClient with the filter
        WebClient webClient = WebClient.builder()
                .baseUrl("http://localhost:8081")
                .build();

        // Create the request body
        Mono<String> requestBody = Mono.just("grant_type=client_credentials");

        // Use WebClient to send a POST request to the token endpoint
        String tokenResponseString = webClient
                .post()
                .uri("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .headers(h -> h.setBasicAuth(getBase64Credentials(clientId, clientSecret)))
                .body(BodyInserters.fromPublisher(requestBody, String.class))
                .retrieve()
                .bodyToMono(String.class)
                .block();

        BearerTokenResponseDto tokenResponse = parseTokens(tokenResponseString);

        // Verify the token response
        assertNotNull(tokenResponse);
        assertNotNull(tokenResponse.getAccessToken());
        assertTrue(tokenResponse.getExpiresIn() > 0);
    }

    private String getBase64Credentials(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        return Base64.getEncoder().encodeToString(credentials.getBytes());
    }

    private BearerTokenResponseDto parseTokens(String jsonString) {
        ObjectMapper objectMapper = new ObjectMapper();

        try {
            JsonNode json = objectMapper.readTree(jsonString);

            if (json.has("access_token") && json.has("expires_in")) {

                var token = json.get("access_token").asText();
                var expiry = json.get("expires_in").asInt();
                //var refreshToken = json.get("refresh_token").asText();
                //var refreshExpiry = json.get("refresh_expires_in").asInt();

                return new BearerTokenResponseDto(token, "Bearer", expiry);
            } else {
                throw new JsonParseException("missing json attributes");
            }

        } catch (JacksonException e) {
            throw new RuntimeException(e);
        }
    }
}