package org.example.wallet.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder

@Configuration
@EnableWebSecurity
class WebSecurityConfiguration {

    @Bean
    fun walletSecurityConfig(http: HttpSecurity): SecurityFilterChain {
        // Security configuration details would go here
        // add the import for http dsl in servlet module
        http {
            authorizeHttpRequests {
                authorize("/credentials/DigitalIDCredential/callback", permitAll)
                authorize("/credentials/UniversityDegreeCredential/callback", permitAll)
                authorize("/credentials/DriversLicenseCredential/callback", permitAll)
                authorize(anyRequest, authenticated)
            }
            csrf {
                disable()
            }
            httpBasic {  }
            formLogin {  }
        }
        return http.build()
    }

    @Bean
    fun userDetailsService() = org.springframework.security.provisioning.InMemoryUserDetailsManager().apply {
        val user = org.springframework.security.core.userdetails.User.withUsername("user")
            .password(passwordEncoder().encode("secret"))
            .roles("USER")
            .build()
        createUser(user)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder()
    }

}