package org.grails.plugin.springsecurity.saml

import grails.plugins.*
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.SecurityFilterPosition
import org.jdom.Document
import org.jdom.input.SAXBuilder
import org.jdom.output.XMLOutputter
import org.jdom.output.Format
import org.springframework.core.io.ClassPathResource;
import grails.plugin.springsecurity.web.authentication.AjaxAwareAuthenticationFailureHandler
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy

import java.util.LinkedHashMap;
import java.util.Map;
import javax.servlet.Filter;
import org.opensaml.core.Version;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations

import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationRequestFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.DefaultSaml2AuthenticationRequestContextResolver;
import org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository
import org.springframework.security.saml2.core.Saml2X509Credential
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import java.security.KeyStore.PasswordProtection
import org.opensaml.security.x509.X509Support
import java.security.cert.X509Certificate
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter

import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.util.matcher.AndRequestMatcher
import javax.servlet.http.HttpServletRequest
import java.util.function.Predicate
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlLogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlLogoutRequestValidator;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml3LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml3LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import java.net.MalformedURLException

class SpringSecuritySamlGrailsPlugin extends Plugin {

    // the version or versions of Grails the plugin is designed for
    String grailsVersion = '3.3.0 > *'
    String author = 'Jeff Wilson'
    String authorEmail = 'jeffwilson70@gmail.com'
    String title = 'Spring Security Saml2 Plugin'
    String description = 'Grails 3 Saml2 Support for Spring Security plugin.'
    String documentation = 'https://jeffwils.github.io/grails-spring-security-saml/'
    String license = 'APACHE'
    //def organization = [name: 'Grails', url: 'http://www.grails.org/']
    def organization = [:]
    def issueManagement = [url: 'https://github.com/jeffwils/grails-spring-security-saml/issues']
    def scm = [url: 'https://github.com/jeffwils/grails-spring-security-saml']
    def profiles = ['web']

    def dependsOn = ['springSecurityCore' : '3.2.0 > *']
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
            'test/**',
            "grails-app/views/error.gsp",
            "UrlMappings",
            'docs/**',
            'scripts/PublishGithub.groovy'
    ]

    // Any additional developers beyond the author specified above.
    def developers = [[ name: "Alvaro Sanchez-Mariscal", email: "alvaro.sanchez@salenda.es" ], [ name: "Feroz Panwaskar", email: "feroz.panwaskar@gmail.com" ],[ name: "Feroz Panwaskar", email: "feroz.panwaskar@gmail.com" ], [ name: "Jeff Beck", email: "beckje01@gmail.com" ], [ name: "Sphoorti Acharya", email: "sphoortiacharya@gmail.com" ]]


    def registrations = []

    Closure doWithSpring() {
        {->
            def conf = SpringSecurityUtils.securityConfig
            if( !isActive( conf ) )
                return

            println 'Configuring Spring Security SAML ...'

            SpringSecurityUtils.registerProvider 'samlAuthenticationProvider'
            SpringSecurityUtils.registerLogoutHandler 'logoutHandler'
            SpringSecurityUtils.registerFilter 'saml2WebSsoAuthenticationFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 1
            SpringSecurityUtils.registerFilter 'saml2AuthenticationRequestFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 2
            SpringSecurityUtils.registerFilter 'saml2LogoutRequestFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 3
            SpringSecurityUtils.registerFilter 'saml2LogoutResponseFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 4
            SpringSecurityUtils.registerFilter 'relyingPartyLogoutFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 6

            successRedirectHandler(SavedRequestAwareAuthenticationSuccessHandler) {
                alwaysUseDefaultTargetUrl = conf.saml.alwaysUseAfterLoginUrl ?: false
                defaultTargetUrl = conf.saml.afterLoginUrl
            }

            logoutSuccessHandler(SimpleUrlLogoutSuccessHandler) {
                defaultTargetUrl = conf.saml.afterLogoutUrl
            }

            def storePass = conf.saml.keyManager.storePass.toCharArray()
            def keystore = loadKeystore(getResource(conf.saml.keyManager.storeFile), storePass)
            String signingKey = conf.saml.metadata.sp.defaults.signingKey
            String verificationKey = conf.saml.metadata.sp.defaults.verificationKey ?: signingKey

            log.debug "Dynamically defining bean metadata providers... "
            def providers = conf.saml.metadata.providers
            providers.each { registrationId, metadataLocation ->
                println "Registering registrationId ${registrationId} from ${metadataLocation}"
                registrations << registrationFromMetadata(conf, registrationId, metadataLocation, keystore)
            }

            userDetailsService(SpringSamlUserDetailsService) {
                grailsApplication = grailsApplication
                authorityClassName = conf.authority.className
                authorityJoinClassName = conf.userLookup.authorityJoinClassName
                authorityNameField = conf.authority.nameField
                samlAutoCreateActive = conf.saml.autoCreate.active
                samlAutoAssignAuthorities = conf.saml.autoCreate.assignAuthorities
                samlAutoCreateKey = conf.saml.autoCreate.key
                samlUserAttributeMappings = conf.saml.userAttributeMappings
                samlUserGroupAttribute = conf.saml.userGroupAttribute
                samlUserGroupToRoleMapping = conf.saml.userGroupToRoleMapping
                userDomainClassName = conf.userLookup.userDomainClassName
            }

            samlResponseAuthenticationConverter(SamlResponseAuthenticationConverter) {
                userDetailsService = ref('userDetailsService')
            }

            samlAuthenticationProvider(OpenSamlAuthenticationProvider) {
                responseAuthenticationConverter = ref('samlResponseAuthenticationConverter')
            }

            authenticationFailureHandler(AjaxAwareAuthenticationFailureHandler) {
                redirectStrategy = ref('redirectStrategy')
                defaultFailureUrl = conf.saml.loginFailUrl ?: '/login/authfail?login_error=1'
                useForward = conf.failureHandler.useForward // false
                ajaxAuthenticationFailureUrl = conf.failureHandler.ajaxAuthFailUrl // '/login/authfail?ajax=true'
                exceptionMappings = conf.failureHandler.exceptionMappings // [:]
                allowSessionCreation = conf.failureHandler.allowSessionCreation // true
            }
            redirectStrategy(DefaultRedirectStrategy) {
                contextRelative = conf.redirectStrategy.contextRelative // false
            }
            sessionFixationProtectionStrategy(SessionFixationProtectionStrategy)

            logoutHandler(SecurityContextLogoutHandler) {
                invalidateHttpSession = true
            }
            springSecurityService(SamlSecurityService) {
                config = conf
                authenticationTrustResolver = ref('authenticationTrustResolver')
                grailsApplication = grailsApplication
                passwordEncoder = ref('passwordEncoder')
                objectDefinitionSource = ref('objectDefinitionSource')
                userDetailsService = ref('userDetailsService')
                userCache = ref('userCache')
            }

            relyingPartyRegistrationRepository(InMemoryRelyingPartyRegistrationRepository, registrations)

            relyingPartyRegistrationRepositoryResolver(DefaultRelyingPartyRegistrationResolver, ref('relyingPartyRegistrationRepository'))

            def defaultRegistrationId = null
            if(conf.saml.metadata.defaultIdp && conf.saml.metadata.sp.defaults.assertionConsumerService) {
                String loginProcessingUrl = null
                try {
                    loginProcessingUrl = new URL(conf.saml.metadata.sp.defaults.assertionConsumerService).getPath()
                } catch(MalformedURLException e) {
                    println "Failed to get path from URL ${conf.saml.metadata.sp.defaults.assertionConsumerService}"
                }
                if (loginProcessingUrl != null) {
                    println "Activating default registration ${conf.saml.metadata.defaultIdp}"
                    defaultRegistrationId = (registrations
                        .find{ it.assertingPartyDetails.entityId == conf.saml.metadata.defaultIdp }.registrationId
                        ?: conf.saml.metadata.defaultIdp)

                    // force the use of defaultIdp registration
                    defaultIdpRegistrationRepositoryResolver(DefaultRegistrationResolver) {
                        relyingPartyRegistrationResolver = ref('relyingPartyRegistrationRepositoryResolver')
                        defaultRegistration = defaultRegistrationId
                    }

                    defaultIdpAuthenticationConverter(Saml2AuthenticationTokenConverter, ref('defaultIdpRegistrationRepositoryResolver'))

                    defaultIdpSaml2WebSsoAuthenticationFilter(Saml2WebSsoAuthenticationFilter, ref('defaultIdpAuthenticationConverter'), loginProcessingUrl) {
                        authenticationRequestRepository = ref('authenticationRequestRepository')
                        authenticationManager = ref('authenticationManager')
                        sessionAuthenticationStrategy = ref('sessionFixationProtectionStrategy')
                        authenticationSuccessHandler = ref('successRedirectHandler')
                        authenticationFailureHandler = ref('authenticationFailureHandler')
                    }
                    SpringSecurityUtils.registerFilter 'defaultIdpSaml2WebSsoAuthenticationFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 5
                }
            }

            securityTagLib(SamlTagLib) {
                springSecurityService = ref('springSecurityService')
                webExpressionHandler = ref('webExpressionHandler')
                webInvocationPrivilegeEvaluator = ref('webInvocationPrivilegeEvaluator')
            }

            contextResolver(DefaultSaml2AuthenticationRequestContextResolver, ref('relyingPartyRegistrationRepositoryResolver'))
            authenticationConverter(Saml2AuthenticationTokenConverter, ref('relyingPartyRegistrationRepositoryResolver'))

            openSamlMetadataResolver(OpenSamlMetadataResolver)

            saml2MetadataFilter(Saml2MetadataFilter, ref('relyingPartyRegistrationRepositoryResolver'), ref('openSamlMetadataResolver'))

            authenticationRequestRepository(HttpSessionSaml2AuthenticationRequestRepository)

            authenticationRequestFactory(OpenSamlAuthenticationRequestFactory)

            String loginProcessingUrl = "/login/saml2/sso/{registrationId}"
            saml2WebSsoAuthenticationFilter(Saml2WebSsoAuthenticationFilter, ref('authenticationConverter'), loginProcessingUrl) {
                authenticationRequestRepository = ref('authenticationRequestRepository')
                authenticationManager = ref('authenticationManager')
                sessionAuthenticationStrategy = ref('sessionFixationProtectionStrategy')
                authenticationSuccessHandler = ref('successRedirectHandler')
                authenticationFailureHandler = ref('authenticationFailureHandler')
            }

            saml2AuthenticationRequestFilter(Saml2WebSsoAuthenticationRequestFilter, ref('contextResolver'), ref('authenticationRequestFactory')) {
                authenticationRequestRepository = ref('authenticationRequestRepository')
            }

            String logoutUrl = "/logout/saml2"
            String logoutResponseUrl = "/logout/saml2/slo";
            String logoutRequestUrl = "/logout/saml2/slo";

            logoutResponseValidator(OpenSamlLogoutResponseValidator)
            logoutResponseResolver(OpenSaml3LogoutResponseResolver, ref('relyingPartyRegistrationRepositoryResolver'))

            logoutRequestRepository(HttpSessionLogoutRequestRepository)
            logoutRequestValidator(OpenSamlLogoutRequestValidator)
            logoutRequestResolver(OpenSaml3LogoutRequestResolver, ref('relyingPartyRegistrationRepositoryResolver'))

            LogoutHandler[] logoutHandlers = [
                new SecurityContextLogoutHandler(),
                new LogoutSuccessEventPublishingLogoutHandler()
            ].toArray(new LogoutHandler[2]);

            saml2LogoutRequestFilter(Saml2LogoutRequestFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                    ref('logoutRequestValidator'), ref('logoutResponseResolver'), logoutHandlers) {
                logoutRequestMatcher = new AndRequestMatcher(
                    new AntPathRequestMatcher(logoutRequestUrl),
                    new ParameterRequestMatcher("SAMLRequest"))
            }

            saml2LogoutResponseFilter(Saml2LogoutResponseFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                    ref('logoutResponseValidator'), ref('logoutSuccessHandler')) {
                logoutRequestMatcher = new AndRequestMatcher(
                    new AntPathRequestMatcher(logoutResponseUrl),
                    new ParameterRequestMatcher("SAMLResponse"))
                logoutRequestRepository = ref('logoutRequestRepository')
            }

            def singleLogoutService = conf.saml.metadata.sp.defaults.singleLogoutService
            def defaultIdp = conf.saml.metadata.defaultIdp
            if(defaultIdp && singleLogoutService) {
                String defaultIdpLogoutResponseUrl = null
                try {
                    defaultIdpLogoutResponseUrl = new URL(singleLogoutService).getPath()
                } catch(MalformedURLException e) {
                    println "Failed to get path from URL ${singleLogoutService}"
                }
                if (defaultIdpLogoutResponseUrl != null) {
                    println "defaultIdpLogoutResponseUrl ${defaultIdpLogoutResponseUrl}"
                    defaultIdpSaml2LogoutRequestFilter(Saml2LogoutRequestFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                            ref('logoutRequestValidator'), ref('logoutResponseResolver'), logoutHandlers) {
                        logoutRequestMatcher = new AndRequestMatcher(
                            new AntPathRequestMatcher(defaultIdpLogoutResponseUrl),
                            new ParameterRequestMatcher("SAMLRequest"))
                    }

                    defaultIdpSaml2LogoutResponseFilter(Saml2LogoutResponseFilter, ref('relyingPartyRegistrationRepositoryResolver'),
                            ref('logoutResponseValidator'), ref('logoutSuccessHandler')) {
                        logoutRequestMatcher = new AndRequestMatcher(
                            new AntPathRequestMatcher(defaultIdpLogoutResponseUrl),
                            new ParameterRequestMatcher("SAMLResponse"))
                        logoutRequestRepository = ref('logoutRequestRepository')
                    }
                    SpringSecurityUtils.registerFilter 'defaultIdpSaml2LogoutRequestFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 7
                    SpringSecurityUtils.registerFilter 'defaultIdpSaml2LogoutResponseFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 8
                }
            }

            logoutRequestSuccessHandler(Saml2RelyingPartyInitiatedLogoutSuccessHandler, ref('logoutRequestResolver'))

            relyingPartyLogoutFilter(LogoutFilter, ref('logoutRequestSuccessHandler'), logoutHandlers) {
                logoutRequestMatcher = new AndRequestMatcher(
                    new AntPathRequestMatcher(logoutUrl),
                    new Saml2RequestMatcher())
            }

            println '...finished configuring Spring Security SAML'
        }
    }

    private static class Saml2RequestMatcher implements RequestMatcher {

        @Override
        public boolean matches(HttpServletRequest request) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null) {
                return false;
            }
            return authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal;
        }

    }

    private static class ParameterRequestMatcher implements RequestMatcher {

        Predicate<String> test = Objects::nonNull;

        String name;

        ParameterRequestMatcher(String name) {
            this.name = name;
        }

        @Override
        public boolean matches(HttpServletRequest request) {
            return this.test.test(request.getParameter(this.name));
        }

    }

    KeyStore loadKeystore(resource, storePass) {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType())
        resource.URL.withInputStream { is ->
            keystore.load(is, storePass)
        }
        return keystore
    }

    def registrationFromMetadata(conf, registrationId, metadataLocation, keystore) {

        String relyingPartyEntityId = conf.saml.metadata.sp.defaults.entityID ?: "{baseUrl}/saml2/service-provider-metadata/{registrationId}"
        String assertionConsumerServiceLocation = conf.saml.metadata.sp.defaults.assertionConsumerService ?: "{baseUrl}/login/saml2/sso/{registrationId}"
        String relyingSingleLogoutServiceLocation = conf.saml.metadata.sp.defaults.singleLogoutService ?: "{baseUrl}/logout/saml2/sso/{registrationId}"

        String signingKey = conf.saml.metadata.sp.defaults.signingKey
        def entryPass = conf.saml.keyManager.passwords.getProperty(signingKey).toCharArray()
        def signingEntry = (PrivateKeyEntry)keystore.getEntry(signingKey, new PasswordProtection(entryPass))
        Saml2X509Credential relyingPartySigningCredential = new Saml2X509Credential(signingEntry.privateKey,
            signingEntry.certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION)

        return RelyingPartyRegistrations.fromMetadataLocation(metadataLocation)
            .registrationId(registrationId)
            .entityId(relyingPartyEntityId)
            .assertionConsumerServiceLocation(assertionConsumerServiceLocation)
            .singleLogoutServiceLocation(relyingSingleLogoutServiceLocation)
            .signingX509Credentials((c) -> c.add(relyingPartySigningCredential))
            .decryptionX509Credentials((c) -> c.add(relyingPartySigningCredential))
            .build()
    }

    void doWithDynamicMethods() {
        // TODO Implement registering dynamic methods to classes (optional)
    }

    void doWithApplicationContext() {
        // TODO Implement post initialization spring config (optional)
    }

    void onChange(Map<String, Object> event) {
        // TODO Implement code that is executed when any artefact that this plugin is
        // watching is modified and reloaded. The event contains: event.source,
        // event.application, event.manager, event.ctx, and event.plugin.
    }

    void onConfigChange(Map<String, Object> event) {
        // TODO Implement code that is executed when the project configuration changes.
        // The event is the same as for 'onChange'.
    }

    void onShutdown(Map<String, Object> event) {
        // TODO Implement code that is executed when the application shuts down (optional)
    }

    private static boolean isActive(conf) {
        final PLUGIN_NOT_AVAILABLE = 'SAML plugin will not be available'
        if( !conf ) {
            // This is unlikely to ever occur due to default configs included in plugins,
            // but historically has always been checked, so keeping.
            println "There is no Spring Security config, $PLUGIN_NOT_AVAILABLE."

            return false
        }
        else if( !conf.active ) {
            println "Spring Security Core plugin is not active, $PLUGIN_NOT_AVAILABLE."

            return false
        }
        else if( !conf.saml.active ) {
            println "saml.active is not true, $PLUGIN_NOT_AVAILABLE."

            return false
        }

        true
    }
}
