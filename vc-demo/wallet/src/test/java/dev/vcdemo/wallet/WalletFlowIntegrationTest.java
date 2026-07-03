package dev.vcdemo.wallet;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.vcdemo.wallet.model.CredentialType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class WalletFlowIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ECKey ISSUER_KEY = key();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static HttpServer issuer;
    private static HttpServer verifier;
    private static String issuerUrl;
    private static String verifierUrl;
    private static volatile String currentType;
    private static volatile String currentState;
    private static volatile String currentNonce;
    private static volatile String lastPresentation;
    private static volatile String lastVpToken;

    @LocalServerPort
    int walletPort;

    @Autowired
    ObjectMapper objectMapper;

    @BeforeAll
    static void startProtocolStubs() throws Exception {
        issuer = HttpServer.create(new InetSocketAddress(0), 0);
        verifier = HttpServer.create(new InetSocketAddress(0), 0);
        issuerUrl = "http://localhost:" + issuer.getAddress().getPort();
        verifierUrl = "http://localhost:" + verifier.getAddress().getPort();
        issuer.createContext("/", WalletFlowIntegrationTest::handleIssuer);
        verifier.createContext("/", WalletFlowIntegrationTest::handleVerifier);
        issuer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        verifier.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        issuer.start();
        verifier.start();
    }

    @AfterAll
    static void stopProtocolStubs() {
        issuer.stop(0);
        verifier.stop(0);
    }

    @DynamicPropertySource
    static void protocolProperties(DynamicPropertyRegistry registry) {
        registry.add("wallet.issuer-url", () -> issuerUrl);
        registry.add("wallet.verifier-url", () -> verifierUrl);
    }

    @ParameterizedTest
    @EnumSource(CredentialType.class)
    void issuesDisplaysAndPresentsCredential(CredentialType type) throws Exception {
        String baseUrl = "http://localhost:" + walletPort;
        HttpResponse<String> indexResponse = get(baseUrl + "/");
        assertThat(indexResponse.statusCode()).isEqualTo(200);
        assertThat(indexResponse.body())
                .contains("Issuer")
                .contains("Verifier")
                .contains("Wallet")
                .contains("health-indicator up");

        HttpResponse<String> issueResponse = HTTP.send(
                HttpRequest.newBuilder(URI.create(baseUrl + "/credentials/issue/" + type.id()))
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(issueResponse.statusCode()).isEqualTo(302);
        String credentialLocation = issueResponse.headers().firstValue("location").orElseThrow();
        String credentialPath = URI.create(credentialLocation).getPath().replaceFirst(";jsessionid=.*$", "");

        HttpResponse<String> detailResponse = get(baseUrl + credentialPath);
        assertThat(detailResponse.statusCode()).isEqualTo(200);
        assertThat(detailResponse.body())
                .contains(type.displayName().replace("'", "&#39;"))
                .contains("Original SD-JWT from issuer")
                .contains("Select claims to disclose");

        String claimsForm = typeClaims(type).stream()
                .map(claim -> "claims=" + claim)
                .collect(java.util.stream.Collectors.joining("&"));
        HttpResponse<String> presentationResponse = HTTP.send(
                HttpRequest.newBuilder(URI.create(baseUrl + credentialPath + "/present"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(claimsForm))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(presentationResponse.statusCode()).isEqualTo(200);
        assertThat(presentationResponse.body())
                .contains("Presentation SD-JWT with key binding")
                .contains("Presentation result")
                .contains("&quot;status&quot; : &quot;verified&quot;");
        assertThat(lastPresentation).contains("~ey").contains(".");
        SignedJWT kbJwt = SignedJWT.parse(lastPresentation.substring(lastPresentation.lastIndexOf('~') + 1));
        assertThat(kbJwt.getHeader().getType()).isEqualTo(new JOSEObjectType("kb+jwt"));

        if (type == CredentialType.PERSONAL_ID) {
            HttpResponse<String> agePresentationResponse = HTTP.send(
                    HttpRequest.newBuilder(URI.create(baseUrl + credentialPath + "/present"))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .POST(HttpRequest.BodyPublishers.ofString(
                                    "presentationProfile=age_over_18&claims=is_over_18"))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            assertThat(agePresentationResponse.statusCode()).isEqualTo(200);
            assertThat(agePresentationResponse.body())
                    .contains("Presentation result")
                    .contains("&quot;status&quot; : &quot;verified&quot;");
            JsonNode vpToken = JSON.readTree(lastVpToken);
            assertThat(vpToken.has("age_over_18")).isTrue();
            assertThat(lastPresentation).contains(encodedClaim("is_over_18"));
            assertThat(lastPresentation).doesNotContain(encodedClaim("birthdate"));
        }
    }

    private static void handleIssuer(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (path.startsWith("/demo/offers/")) {
                currentType = path.substring(path.lastIndexOf('/') + 1);
                json(exchange, 200, Map.of("pre_authorized_code", "demo-code"));
            } else if (path.equals("/oauth2/token")) {
                json(exchange, 200, Map.of("access_token", "demo-token", "token_type", "Bearer"));
            } else if (path.equals("/nonce")) {
                json(exchange, 200, Map.of("c_nonce", "issuer-nonce"));
            } else if (path.equals("/credential")) {
                JsonNode body = JSON.readTree(exchange.getRequestBody());
                SignedJWT proof = SignedJWT.parse(body.at("/proofs/jwt/0").asText());
                ECKey holderKey = ECKey.parse(proof.getHeader().getJWK().toJSONObject());
                json(exchange, 200, Map.of("credentials", List.of(Map.of(
                        "credential", issueCredential(currentType, holderKey)))));
            } else if (path.equals("/jwks")) {
                json(exchange, 200, Map.of("keys", List.of(ISSUER_KEY.toPublicJWK().toJSONObject())));
            } else if (path.equals("/actuator/health")) {
                json(exchange, 200, Map.of("status", "UP"));
            } else {
                json(exchange, 404, Map.of("error", "not_found"));
            }
        } catch (Exception e) {
            json(exchange, 500, Map.of("error", e.getMessage()));
        }
    }

    private static void handleVerifier(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (path.startsWith("/api/presentations/") && exchange.getRequestMethod().equals("POST")) {
                currentType = path.substring(path.lastIndexOf('/') + 1);
                currentState = UUID.randomUUID().toString();
                currentNonce = UUID.randomUUID().toString();
                json(exchange, 200, Map.of("transaction_id", "tx-1"));
            } else if (path.equals("/api/presentations/tx-1/request")) {
                json(exchange, 200, Map.of(
                        "client_id", "redirect_uri:" + verifierUrl + "/oid4vp/response",
                        "response_type", "vp_token",
                        "response_mode", "direct_post",
                        "response_uri", verifierUrl + "/oid4vp/response",
                        "nonce", currentNonce,
                        "state", currentState,
                        "dcql_query", Map.of("credentials", List.of(Map.of(
                                "id", currentType,
                                "format", "dc+sd-jwt",
                                "meta", Map.of("vct_values", List.of(
                                        issuerUrl + "/credentials/types/" + credentialTypeFor(currentType))))))));
            } else if (path.equals("/oid4vp/response")) {
                String form = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                Map<String, String> values = parseForm(form);
                lastVpToken = values.get("vp_token");
                JsonNode vpToken = JSON.readTree(values.get("vp_token"));
                lastPresentation = vpToken.at("/" + currentType + "/0").asText();
                json(exchange, 200, Map.of("redirect_uri", verifierUrl + "/api/presentations/tx-1"));
            } else if (path.equals("/api/presentations/tx-1")) {
                json(exchange, 200, Map.of(
                        "transaction_id", "tx-1",
                        "status", "verified",
                        "credential_type", currentType,
                        "issuer", issuerUrl));
            } else if (path.equals("/actuator/health")) {
                json(exchange, 200, Map.of("status", "UP"));
            } else {
                json(exchange, 404, Map.of("error", "not_found"));
            }
        } catch (Exception e) {
            json(exchange, 500, Map.of("error", e.getMessage()));
        }
    }

    private static String issueCredential(String type, ECKey holderKey) throws Exception {
        List<String> disclosures = new ArrayList<>();
        List<String> digests = new ArrayList<>();
        for (String claim : typeClaims(CredentialType.fromId(type))) {
            String disclosure = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    JSON.writeValueAsBytes(List.of("salt", claim, claimValue(claim))));
            disclosures.add(disclosure);
            digests.add(hash(disclosure));
        }
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("dc+sd-jwt"))
                        .keyID(ISSUER_KEY.getKeyID())
                        .build(),
                new JWTClaimsSet.Builder()
                        .issuer(issuerUrl)
                        .issueTime(Date.from(Instant.now()))
                        .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                        .claim("vct", issuerUrl + "/credentials/types/" + type)
                        .claim("_sd_alg", "sha-256")
                        .claim("_sd", digests)
                        .claim("cnf", Map.of("jwk", holderKey.toJSONObject()))
                        .build());
        jwt.sign(new ECDSASigner(ISSUER_KEY));
        return jwt.serialize() + "~" + String.join("~", disclosures) + "~";
    }

    private static List<String> typeClaims(CredentialType type) {
        return switch (type) {
            case PERSONAL_ID -> List.of(
                    "given_name", "family_name", "birthdate", "nationality", "document_number", "is_over_18");
            case UNIVERSITY_DIPLOMA -> List.of(
                    "given_name", "family_name", "degree", "field_of_study", "university", "graduation_date");
            case DRIVERS_LICENSE -> List.of(
                    "given_name", "family_name", "birthdate", "license_number", "issuing_country",
                    "issue_date", "expiry_date", "vehicle_categories");
        };
    }

    private static Object claimValue(String claim) {
        return "is_over_18".equals(claim) ? true : "demo-" + claim;
    }

    private static String credentialTypeFor(String profileId) {
        return "age_over_18".equals(profileId) ? "personal_id" : profileId;
    }

    private static String encodedClaim(String claimName) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                JSON.writeValueAsBytes(List.of("salt", claimName, claimValue(claimName))));
    }

    private HttpResponse<String> get(String uri) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create(uri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, String> parseForm(String form) {
        Map<String, String> values = new LinkedHashMap<>();
        for (String pair : form.split("&")) {
            String[] parts = pair.split("=", 2);
            values.put(
                    java.net.URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                    java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
        }
        return values;
    }

    private static void json(HttpExchange exchange, int status, Object body) throws IOException {
        byte[] bytes = JSON.writeValueAsBytes(body);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static String hash(String value) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII)));
    }

    private static ECKey key() {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .algorithm(JWSAlgorithm.ES256)
                    .keyID("issuer-key")
                    .generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
