package org.example.sd.web

import com.authlete.sd.Disclosure
import com.authlete.sd.SDJWT
import com.nimbusds.jwt.SignedJWT
import org.example.sd.model.IdentityCredential
import org.example.sd.service.SelectiveDisclosureService
import org.example.sd.web.Templates.CREDENTIALS
import org.example.sd.web.Templates.INDEX
import org.example.sd.web.Templates.PRESENTATION
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ModelAttribute

@Suppress("TooManyFunctions")
@Controller
class SelectiveDisclosureController(
    private val selectiveDisclosureService: SelectiveDisclosureService,
) {
    @GetMapping("/")
    fun index(): String = INDEX

    @GetMapping("/credentials")
    fun credentials(): String = CREDENTIALS

    @GetMapping("/presentation")
    fun presentation(model: Model): String {
        model.addAttribute("age_verification", selectiveDisclosureService.verifyAge())
        return PRESENTATION
    }

    @ModelAttribute("identityCredential")
    fun identityCredential(): IdentityCredential = selectiveDisclosureService.getIdentityCredential()

    @ModelAttribute("identityCredentialSerialized")
    fun identityCredentialSerialized(): String =
        selectiveDisclosureService.serialize(
            selectiveDisclosureService.getIdentityCredential(),
        )

    @ModelAttribute("undisclosedFields")
    fun undisclosedFields(): MutableMap<String, Any> = selectiveDisclosureService.getUndisclosedFields()

    @ModelAttribute("disclosures")
    fun disclosures(): MutableList<Disclosure> = selectiveDisclosureService.getDisclosures()

    @ModelAttribute("credentialJwt")
    fun credentialJwt(): SignedJWT = selectiveDisclosureService.getCredentialJwt()

    @ModelAttribute("sdJwt")
    fun sdJwt(): SDJWT = selectiveDisclosureService.getSdjwt()

    @ModelAttribute("serializedSdJwt")
    fun serializedSdJwt(): String = selectiveDisclosureService.getSerializedSdJwt()

    @ModelAttribute("presentationSdJwt")
    fun presentationSdJwt(): SDJWT = selectiveDisclosureService.getPresentationSdJwt()

    @ModelAttribute("serializedPresentationSdJwt")
    fun serializedPresentationSdJwt(): String = selectiveDisclosureService.getSerializedPresentationSdJwt()
}
