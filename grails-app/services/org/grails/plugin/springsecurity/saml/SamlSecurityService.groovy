package org.grails.plugin.springsecurity.saml

import grails.plugin.springsecurity.SpringSecurityService
import groovy.util.logging.Slf4j

/**
 * A subclass of {@link SpringSecurityService} to replace {@link getCurrentUser()}
 * method. The parent implementation performs a database load, but we do not have
 * database users here, so we simply return the authentication details.
 *
 * @author alvaro.sanchez
 */
@Slf4j('logger')
class SamlSecurityService extends SpringSecurityService {
    def userCache
    static transactional = false
    def config

    Object getCurrentUser() {
        logger.debug("SamlSecurityService getCurrentUser")
        def userDetails
        if (!isLoggedIn()) {
            userDetails = null
        } else {
            userDetails = getAuthentication().details
            if ( config?.saml.autoCreate.active ) {
                userDetails =  getCurrentPersistedUser(userDetails)
            }
        }
        return userDetails
    }

    private Object getCurrentPersistedUser(userDetails) {
        if (userDetails) {
            String className = config?.userLookup.userDomainClassName
            String userKey = config?.saml.autoCreate.key
            if (className && userKey) {
                Class<?> userClass = grailsApplication.getDomainClass(className)?.clazz
                return userClass."findBy${userKey.capitalize()}"(userDetails."$userKey")
            }
        } else { return null}
    }

    reactor.bus.Bus sendAndReceive(java.lang.Object obj, groovy.lang.Closure closure) {
        return null
    }
}
