package dev.vcdemo.wallet.model;

import java.util.Arrays;
import java.util.List;

public enum CredentialType {
    PERSONAL_ID("personal_id", "Personal ID", List.of(
            new PresentationProfile("personal_id", "Full Personal ID"),
            new PresentationProfile("age_over_18", "Age over 18"))),
    UNIVERSITY_DIPLOMA("university_diploma", "University Diploma", List.of(
            new PresentationProfile("university_diploma", "University Diploma"))),
    DRIVERS_LICENSE("drivers_license", "Driver's License", List.of(
            new PresentationProfile("drivers_license", "Driver's License")));

    private final String id;
    private final String displayName;
    private final List<PresentationProfile> presentationProfiles;

    CredentialType(String id, String displayName, List<PresentationProfile> presentationProfiles) {
        this.id = id;
        this.displayName = displayName;
        this.presentationProfiles = presentationProfiles;
    }

    public String id() {
        return id;
    }

    public String displayName() {
        return displayName;
    }

    public List<PresentationProfile> presentationProfiles() {
        return presentationProfiles;
    }

    public String defaultPresentationProfileId() {
        return presentationProfiles.getFirst().id();
    }

    public PresentationProfile presentationProfile(String id) {
        return presentationProfiles.stream()
                .filter(profile -> profile.id().equals(id))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Credential type " + this.id + " cannot satisfy verifier profile: " + id));
    }

    public static CredentialType fromId(String id) {
        return Arrays.stream(values())
                .filter(type -> type.id.equals(id))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown credential type: " + id));
    }

    public record PresentationProfile(String id, String displayName) {
    }
}
