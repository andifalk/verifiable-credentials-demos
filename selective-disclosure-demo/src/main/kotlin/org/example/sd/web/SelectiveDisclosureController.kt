package org.example.sd.web

import com.authlete.sd.Disclosure
import com.authlete.sd.SDJWT
import com.nimbusds.jwt.SignedJWT
import org.example.sd.model.IdentityCredential
import org.example.sd.service.SelectiveDisclosureService
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ModelAttribute
import org.springframework.web.bind.annotation.RequestParam
import java.util.stream.Collectors

@Controller
class SelectiveDisclosureController(private val selectiveDisclosureService: SelectiveDisclosureService) {

    @GetMapping("/")
    fun index(model: Model): String {
        return "index"
    }

    @GetMapping("/credentials")
    fun credentials(model: Model): String {
        val identityCredential = selectiveDisclosureService.createIdentityCredential()
        val undisclosedFields = selectiveDisclosureService.undisclosedFields(identityCredential)
        val disclosedFields = selectiveDisclosureService.discloseFields(identityCredential)
        val credentialJwt = selectiveDisclosureService.createCredentialJwt(undisclosedFields, disclosedFields)
        val sdJwt = selectiveDisclosureService.createSdJwt(undisclosedFields, disclosedFields)
        val disclosuresString = sdJwt.disclosures.stream().map { "~$it" }.collect(Collectors.joining())
        model.addAttribute("rawCredentials", selectiveDisclosureService.serialize(identityCredential))
        model.addAttribute("undisclosedFields", undisclosedFields)
        model.addAttribute("disclosedFields", disclosedFields)
        model.addAttribute("credentialJwt", credentialJwt)
        model.addAttribute("sdJwt", sdJwt)
        model.addAttribute("sdJwtDisclosures", disclosuresString)
        return "credentials"
    }

    @ModelAttribute("identityCredential")
    fun identityCredential(): String {
        return selectiveDisclosureService.serialize(selectiveDisclosureService.createIdentityCredential())
    }
}
