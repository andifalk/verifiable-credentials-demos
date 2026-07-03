package dev.vcdemo.wallet.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

@Service
public class AppHealthService {

    private static final Logger log = LoggerFactory.getLogger(AppHealthService.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(1);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String issuerUrl;
    private final String verifierUrl;
    private final String walletUrl;

    public AppHealthService(ObjectMapper objectMapper,
            @Value("${wallet.issuer-url}") String issuerUrl,
            @Value("${wallet.verifier-url}") String verifierUrl,
            @Value("${wallet.base-url}") String walletUrl) {
        this.objectMapper = objectMapper;
        this.issuerUrl = issuerUrl;
        this.verifierUrl = verifierUrl;
        this.walletUrl = walletUrl.replaceAll("/+$", "");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(TIMEOUT)
                .build();
    }

    public WalletHealth current() {
        return new WalletHealth(
                check("Issuer", issuerUrl),
                check("Verifier", verifierUrl),
                new AppStatus("Wallet", port(walletUrl), walletUrl, true));
    }

    private AppStatus check(String name, String baseUrl) {
        String normalized = baseUrl.replaceAll("/+$", "");
        String healthUrl = normalized + "/actuator/health";
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(healthUrl))
                    .timeout(TIMEOUT)
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            boolean up = response.statusCode() >= 200
                    && response.statusCode() < 300
                    && "UP".equals(objectMapper.readTree(response.body()).path("status").asText());
            log.info("Wallet app health check name={} url={} http_status={} up={}",
                    name, healthUrl, response.statusCode(), up);
            return new AppStatus(name, port(normalized), normalized, up);
        } catch (Exception e) {
            log.info("Wallet app health check name={} url={} up=false error={}",
                    name, healthUrl, e.getMessage());
            return new AppStatus(name, port(normalized), normalized, false);
        }
    }

    private String port(String baseUrl) {
        try {
            int port = URI.create(baseUrl).getPort();
            return port > 0 ? ":" + port : "";
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    public record WalletHealth(AppStatus issuer, AppStatus verifier, AppStatus wallet) {
    }

    public record AppStatus(String name, String port, String url, boolean up) {
    }
}
