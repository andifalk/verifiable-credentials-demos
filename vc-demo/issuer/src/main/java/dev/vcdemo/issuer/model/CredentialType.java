package dev.vcdemo.issuer.model;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public enum CredentialType {
    PERSONAL_ID(
            "personal_id",
            "Personal ID",
            List.of("given_name", "family_name", "birthdate", "nationality", "document_number", "is_over_18"),
            Map.of(
                    "given_name", "Erika",
                    "family_name", "Mustermann",
                    "birthdate", "1990-01-01",
                    "nationality", "DE",
                    "document_number", "PID-DEMO-0001",
                    "is_over_18", true)),
    UNIVERSITY_DIPLOMA(
            "university_diploma",
            "University Diploma",
            List.of("given_name", "family_name", "degree", "field_of_study", "university", "graduation_date"),
            Map.of(
                    "given_name", "Erika",
                    "family_name", "Mustermann",
                    "degree", "Master of Science",
                    "field_of_study", "Computer Science",
                    "university", "Demo University",
                    "graduation_date", "2025-07-15")),
    DRIVERS_LICENSE(
            "drivers_license",
            "Driver's License",
            List.of("given_name", "family_name", "birthdate", "license_number", "issuing_country",
                    "issue_date", "expiry_date", "vehicle_categories"),
            Map.of(
                    "given_name", "Erika",
                    "family_name", "Mustermann",
                    "birthdate", "1990-01-01",
                    "license_number", "DL-DEMO-0001",
                    "issuing_country", "DE",
                    "issue_date", "2024-01-01",
                    "expiry_date", "2039-01-01",
                    "vehicle_categories", List.of("B")));

    private final String configurationId;
    private final String displayName;
    private final List<String> claims;
    private final Map<String, Object> sampleClaims;

    CredentialType(String configurationId, String displayName, List<String> claims,
            Map<String, Object> sampleClaims) {
        this.configurationId = configurationId;
        this.displayName = displayName;
        this.claims = claims;
        this.sampleClaims = sampleClaims;
    }

    public String configurationId() {
        return configurationId;
    }

    public String displayName() {
        return displayName;
    }

    public List<String> claims() {
        return claims;
    }

    public Map<String, Object> sampleClaims() {
        return sampleClaims;
    }

    public static CredentialType fromConfigurationId(String id) {
        return Arrays.stream(values())
                .filter(type -> type.configurationId.equals(id))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown credential configuration: " + id));
    }
}
