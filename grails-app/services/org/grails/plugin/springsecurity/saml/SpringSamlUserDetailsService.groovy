/* Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.grails.plugin.springsecurity.saml

import grails.gorm.transactions.Transactional

import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import groovy.util.logging.Slf4j
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal
import grails.plugin.springsecurity.SpringSecurityUtils
import org.springframework.security.core.userdetails.UserDetails
import groovy.lang.MissingPropertyException

/**
 * A {@link GormUserDetailsService} extension to read attributes from a LDAP-backed
 * SAML identity provider. It also reads roles from database
 *
 * @author alvaro.sanchez
 */
@Transactional
@Slf4j('logger')
class SpringSamlUserDetailsService extends GormUserDetailsService {

    String authorityClassName
    String authorityJoinClassName
    String authorityNameField
    Boolean samlAutoCreateActive
    Boolean samlAutoAssignAuthorities = true
    String samlAutoCreateKey
    Map samlUserAttributeMappings
    Map samlUserGroupToRoleMapping
    String samlUserGroupAttribute
    String userDomainClassName

    @Value( '${grails.plugin.springsecurity.saml.useLocalRoles:false}' )
    Boolean samlUseLocalRoles


    public UserDetails loadUserBySAML(Saml2AuthenticatedPrincipal principal) throws UsernameNotFoundException {
        logger.debug("Loading user - ${principal.toString()}")
        if (principal) {
            String username = getSamlUsername(principal)
            logger.debug("Username ${username}")
            if (!username) {
                throw new UsernameNotFoundException("No username supplied in saml response.")
            }

            def user = generateSecurityUser(username)
            logger.debug("Generated User ${user.username}")
            user = mapAdditionalAttributes(principal, user)
            if (user) {
                def grantedAuthorities = getAuthoritiesForUser(principal, username)
                if (samlAutoCreateActive) {
                    user = saveUser(user.class, user, grantedAuthorities)
                    // load any new local DB roles
                    grantedAuthorities.addAll(
                        determineLocalRoles( username )
                    )
                }

                logger.debug("User Class ${user?.class}")
                logger.debug("User - username ${user?.username}")
                logger.debug("User - id ${user?.id}")
                def userDetails = createUserDetails(user, grantedAuthorities)
                logger.debug("User Details ${userDetails.toString()}")
                if(userDetails instanceof SamlUserDetails) {
                    def samlAttributes = [:]
                    samlUserAttributeMappings.each { key, value ->
                        try {
                            samlAttributes."$key" = [user."$key"]
                        } catch(MissingPropertyException e) {
                            logger.warn("Failed to get SAML attribute '$key' from ${user.getClass()}. Add the SAML attribute to your User domain class.")
                            logger.error "Error: ${e.message}", e
                            def samlValue = principal.getAttribute(value)
                            if (samlValue) {
                                samlAttributes."$key" = samlValue
                            }
                        }
                    }
                    userDetails.setAttributes(samlAttributes)
                }

                return userDetails
            } else {
                throw new InstantiationException('could not instantiate new user')
            }
        }
    }

    protected String getSamlUsername(Saml2AuthenticatedPrincipal principal) {
        logger.debug("getSamlUsername()")
        def usernameAttr = samlUserAttributeMappings?.username
        if ( usernameAttr ) {
            def value = principal.getFirstAttribute(usernameAttr).toString()
            logger.debug("Username using attribute '${usernameAttr}': ${value}")
            return value
        } else {
            // if no mapping provided for username attribute then assume it is the returned subject in the assertion
            return principal.name
        }
    }

    protected Object mapAdditionalAttributes(Saml2AuthenticatedPrincipal principal, user) {
        samlUserAttributeMappings.each { key, value ->
            def samlValue = principal.getFirstAttribute(value).toString()
            if (samlValue) {
                user."$key" = samlValue
            }
        }
        user
    }

    protected Collection<GrantedAuthority> getAuthoritiesForUser(Saml2AuthenticatedPrincipal principal, String username) {
        Set<GrantedAuthority> authorities = new HashSet<SimpleGrantedAuthority>()

        logger.debug "Determining Authorities for $username"
        if (samlUseLocalRoles) {
            authorities.addAll(
                determineLocalRoles(username)
            )

        }
        authorities.addAll (
            determineSamlRoles( principal )
        )

        logger.debug("Returning Authorities with ${authorities?.size()} Authorities added.")
        authorities
    }

    private Set<SimpleGrantedAuthority> determineSamlRoles(Saml2AuthenticatedPrincipal principal) {
        logger.debug('Using samlUserGroupAttribute: ' + samlUserGroupAttribute)
        String[] samlGroups = principal.getAttribute(samlUserGroupAttribute)*.toString()
        logger.debug('Using samlGroups: ' + samlGroups)
        logger.debug('User samlUserGroupToRoleMapping: ' + samlUserGroupToRoleMapping)

        Set<SimpleGrantedAuthority> authorities = new HashSet<>()
        samlGroups.eachWithIndex { groupName, groupIdx ->
            logger.debug("Group Name From SAML: ${groupName}")
            String role = samlUserGroupToRoleMapping?.find { it?.value == groupName }?.key
            def authority
            if (role) {
                logger.debug("Found Role")
                authority = getRole(role)
            }
            if (authority) {
                logger.debug("Found Authority Adding it")
                authorities.add(new SimpleGrantedAuthority(authority."$authorityNameField"))
            }
        }

        authorities
    }

    private Set<SimpleGrantedAuthority> determineLocalRoles( String username ) {
        logger.debug( 'Using role assignments from local database.' )

        Set<SimpleGrantedAuthority> authorities = new HashSet<>()
        def user = userClass.findByUsername( username )
        if( user ) {
            loadAuthorities( user, username, true ).each { authority ->
                authorities.add(
                    new SimpleGrantedAuthority( authority.authority )
                )
            }
            logger.debug( "Added ${authorities.size()} role(s) from local database." )
        }
        else {
            logger.debug( "User $username does not exist in local database, unable to load local roles.")
        }

        authorities
    }


    private Object generateSecurityUser(username) {
        userClass.newInstance( username: username, password: 'password' )
    }

    private def saveUser(userClazz, user, authorities) {
        logger.debug("Saving User")
        if (userClazz && samlAutoCreateActive && samlAutoCreateKey && authorityNameField && authorityJoinClassName) {

            Map whereClause = [:]
            whereClause.put "$samlAutoCreateKey".toString(), user."$samlAutoCreateKey"
            Class<?> joinClass = grailsApplication.getDomainClass(authorityJoinClassName)?.clazz
            logger.debug("Before With Transaction")

                logger.debug("Saving User")
                def existingUser
                userClazz.withTransaction {
                    existingUser = userClazz.findWhere(whereClause)
                }

                if (!existingUser) {
                    logger.debug("User Doesn't Exist.....save it")
                    userClazz.withTransaction {
                        user.save(flush:true)
                        //if (!user.save()) throw new UsernameNotFoundException("Could not save user ${user}");
                    }

                } else {
                    logger.debug("User Exists.....update its properties")
                    user = updateUserProperties(existingUser, user)

                    if (samlAutoAssignAuthorities) {
                        logger.debug("Remove all Authorities")
                        joinClass.withTransaction {
                            joinClass.removeAll user
                        }


                    }
                    logger.debug("Now Save the User")
                    userClazz.withTransaction {
                        user.save()
                    }

                }

                if (samlAutoAssignAuthorities) {
                    logger.debug("go thru the list of authorities")
                    authorities.each { grantedAuthority ->
                        logger.debug("Working on Authority ${grantedAuthority}.${authorityNameField}")
                        def role = getRole(grantedAuthority."${authorityNameField}")
                        logger.debug("SAVING USER_ROLE - User name ${user.username}")
                        logger.debug("SAVING USER_ROLE - Role name ${role.authority}")
                        logger.debug("SAVING USER_ROLE - User Id ${user.id}")
                        logger.debug("SAVING USER_ROLE - Role Id ${role.id}")
                        joinClass.withTransaction {
                            if (!joinClass.exists(user.id, role.id)){
                                joinClass.create(user, role, true)
                                logger.debug 'Allocated new role to user.'
                            }
                            else {
                                logger.debug 'User and role already exists, nothing created.'
                            }
                        }
                    }
                }
        }
        return user
    }

    private Object updateUserProperties(existingUser, user) {
        samlUserAttributeMappings.each { key, value ->
            existingUser."$key" = user."$key"
        }
        return existingUser
    }

    private Object getRole(String authority) {
        if (authority && authorityNameField && authorityClassName) {
            logger.debug("getRole - param -> ${authority}")
            Class<?> RoleClass = grailsApplication.getDomainClass(authorityClassName).clazz
            Map whereClause = [:]
            whereClause.put "$authorityNameField".toString(), authority
            if (RoleClass) {
                RoleClass.withTransaction {
                    logger.debug("Where clause -> ${whereClause}")
                    def returnVal = RoleClass.findWhere(whereClause)
                    logger.debug("Return Value from getRole Class-> ${returnVal?.class}  Value -> ${returnVal}")
                    returnVal
                }
            } else {
                throw new ClassNotFoundException("domain class ${authorityClassName} not found")
            }
        }
    }

    private Class getUserClass() {
        logger.debug("Attempting to load UserClass with name: ${userDomainClassName}")

        if (!userDomainClassName) {
            throw new ClassNotFoundException( 'Security user domain class undefined.' )
        }

        Class userClass = grailsApplication.getClassForName(userDomainClassName)
        if( !userClass ) {
            throw new ClassNotFoundException( "Domain class ${userDomainClassName} not found." )
        }
        logger.debug("Loaded UserClass: ${userClass}")

        userClass
    }

    protected UserDetails createUserDetails(user, Collection<GrantedAuthority> authorities) {
        def conf = SpringSecurityUtils.securityConfig

        String usernamePropertyName = conf.userLookup.usernamePropertyName
        String passwordPropertyName = conf.userLookup.passwordPropertyName
        String enabledPropertyName = conf.userLookup.enabledPropertyName
        String accountExpiredPropertyName = conf.userLookup.accountExpiredPropertyName
        String accountLockedPropertyName = conf.userLookup.accountLockedPropertyName
        String passwordExpiredPropertyName = conf.userLookup.passwordExpiredPropertyName

        String username = user."$usernamePropertyName"
        String password = user."$passwordPropertyName"
        boolean enabled = enabledPropertyName ? user."$enabledPropertyName" : true
        boolean accountExpired = accountExpiredPropertyName ? user."$accountExpiredPropertyName" : false
        boolean accountLocked = accountLockedPropertyName ? user."$accountLockedPropertyName" : false
        boolean passwordExpired = passwordExpiredPropertyName ? user."$passwordExpiredPropertyName" : false

        def samlAttributes = [:]
        samlUserAttributeMappings.each { key, value ->
            try {
                samlAttributes."$key" = [user."$key"]
            } catch(MissingPropertyException e) {
                logger.warn("Failed to get SAML attribute '$key' from ${user.getClass()}. Add the SAML attribute to your User domain class.")
                logger.error "Error: ${e.message}", e
            }
        }

        new SamlUserDetails(username, password, enabled, !accountExpired, !passwordExpired,
            !accountLocked, authorities, user.id, samlAttributes)
    }
}
