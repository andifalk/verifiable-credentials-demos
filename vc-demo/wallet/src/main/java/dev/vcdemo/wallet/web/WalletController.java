package dev.vcdemo.wallet.web;

import dev.vcdemo.wallet.model.CredentialType;
import dev.vcdemo.wallet.model.WalletCredential;
import dev.vcdemo.wallet.service.AppHealthService;
import dev.vcdemo.wallet.service.IssuerClient;
import dev.vcdemo.wallet.service.VerifierClient;
import dev.vcdemo.wallet.service.WalletCredentialStore;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
public class WalletController {

    private final WalletCredentialStore store;
    private final IssuerClient issuerClient;
    private final VerifierClient verifierClient;
    private final AppHealthService appHealthService;

    public WalletController(WalletCredentialStore store, IssuerClient issuerClient,
            VerifierClient verifierClient, AppHealthService appHealthService) {
        this.store = store;
        this.issuerClient = issuerClient;
        this.verifierClient = verifierClient;
        this.appHealthService = appHealthService;
    }

    @GetMapping("/")
    String index(Model model) {
        model.addAttribute("credentialTypes", CredentialType.values());
        model.addAttribute("credentials", store.all());
        model.addAttribute("health", appHealthService.current());
        return "index";
    }

    @PostMapping("/credentials/issue/{type}")
    String issue(@PathVariable String type, RedirectAttributes redirectAttributes) {
        try {
            WalletCredential credential = issuerClient.issue(CredentialType.fromId(type));
            store.save(credential);
            redirectAttributes.addFlashAttribute("message",
                    credential.type().displayName() + " issued and stored in the wallet.");
            return "redirect:/credentials/" + credential.id();
        } catch (RuntimeException e) {
            redirectAttributes.addFlashAttribute("error", e.getMessage());
            return "redirect:/";
        }
    }

    @GetMapping("/credentials/{id}")
    String credential(@PathVariable String id, Model model) {
        WalletCredential credential = requireCredential(id);
        model.addAttribute("credential", credential);
        model.addAttribute("selectedPresentationProfile", credential.type().defaultPresentationProfileId());
        return "credential";
    }

    @PostMapping("/credentials/{id}/present")
    String present(@PathVariable String id,
            @RequestParam(name = "presentationProfile", required = false) String presentationProfile,
            @RequestParam(name = "claims", required = false) List<String> claims,
            Model model) {
        WalletCredential credential = requireCredential(id);
        String profile = presentationProfile == null
                ? credential.type().defaultPresentationProfileId()
                : presentationProfile;
        model.addAttribute("credential", credential);
        model.addAttribute("selectedPresentationProfile", profile);
        model.addAttribute("selectedClaims", claims == null ? List.of() : claims);
        try {
            VerifierClient.PresentationOutcome outcome =
                    verifierClient.present(credential, profile, claims == null ? List.of() : claims);
            model.addAttribute("presentation", outcome.presentationSdJwt());
            model.addAttribute("transactionId", outcome.transactionId());
            model.addAttribute("verifierResult", outcome.verifierResult().toPrettyString());
        } catch (RuntimeException e) {
            model.addAttribute("error", e.getMessage());
        }
        return "credential";
    }

    private WalletCredential requireCredential(String id) {
        return store.find(id)
                .orElseThrow(() -> new IllegalArgumentException("Credential not found: " + id));
    }
}
