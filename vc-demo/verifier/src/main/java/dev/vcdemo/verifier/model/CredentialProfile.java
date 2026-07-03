package dev.vcdemo.verifier.model;

import java.util.Arrays;
import java.util.List;

public enum CredentialProfile {
    PERSONAL_ID("personal_id", "personal_id",
            List.of("given_name", "family_name", "birthdate", "nationality", "document_number")),
    AGE_OVER_18("age_over_18", "personal_id", List.of("is_over_18")),
    UNIVERSITY_DIPLOMA("university_diploma", "university_diploma",
            List.of("given_name", "family_name", "degree", "field_of_study", "university", "graduation_date")),
    DRIVERS_LICENSE("drivers_license", "drivers_license",
            List.of("given_name", "family_name", "birthdate", "license_number", "issuing_country",
                    "issue_date", "expiry_date", "vehicle_categories"));

    private final String id;
    private final String credentialTypeId;
    private final List<String> requiredClaims;

    CredentialProfile(String id, String credentialTypeId, List<String> requiredClaims) {
        this.id = id;
        this.credentialTypeId = credentialTypeId;
        this.requiredClaims = requiredClaims;
    }

    public String id() {
        return id;
    }

    public String credentialTypeId() {
        return credentialTypeId;
    }

    public List<String> requiredClaims() {
        return requiredClaims;
    }

    public static CredentialProfile fromId(String id) {
        return Arrays.stream(values())
                .filter(profile -> profile.id.equals(id))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown credential profile: " + id));
    }
}
