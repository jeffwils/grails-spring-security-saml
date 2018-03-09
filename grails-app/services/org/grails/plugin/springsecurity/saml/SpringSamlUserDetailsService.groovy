package org.grails.plugin.springsecurity.saml

import grails.converters.JSON
import grails.plugin.springsecurity.SpringSecurityUtils

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
import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import grails.transaction.Transactional
import grails.util.Holders
import groovy.util.logging.Slf4j
import org.opensaml.saml2.core.Attribute
import org.springframework.beans.BeanUtils
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.saml.SAMLCredential
import org.springframework.security.saml.userdetails.SAMLUserDetailsService
import org.springframework.dao.DataAccessException
import grails.core.GrailsApplication

/**
 * A {@link GormUserDetailsService} extension to read attributes from a LDAP-backed
 * SAML identity provider. It also reads roles from database
 *
 * @author alvaro.sanchez
 */
@Transactional
class SpringSamlUserDetailsService extends GormUserDetailsService implements SAMLUserDetailsService {

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



    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        log.debug("Loading user - ${credential.toString()}")
        if (credential) {
            String username = getSamlUsername(credential)
            log.debug("Username ${username}")
            if (!username) {
                throw new UsernameNotFoundException("No username supplied in saml response.")
            }

            def user = generateSecurityUser(username)
            log.debug("Generated User ${user.username}")
            user = mapAdditionalAttributes(credential, user)
            if (user) {
                log.debug "Loading database roles for $username..."
                def authorities = getAuthoritiesForUser(credential, username)

                def grantedAuthorities = []
                if (samlAutoCreateActive) {
                    user = saveUser(user.class, user, authorities)

                    //TODO move to function
                    Map whereClause = [:]
                    whereClause.put "user", user
                    Class<?> UserRoleClass = grailsApplication.getDomainClass(authorityJoinClassName)?.clazz
                    UserRoleClass.withTransaction {
                        def auths = UserRoleClass.findAllWhere(whereClause).collect { it.role }

                        auths.each { authority ->
                            grantedAuthorities.add(new SimpleGrantedAuthority(authority."$authorityNameField"))

                        }
                    }
                }
                else {
                    grantedAuthorities = authorities
                }
                log.debug("User Class ${user?.class}")
                log.debug("User - username ${user?.username}")
                log.debug("User - id ${user?.id}")
                def userDetails = createUserDetails(user, grantedAuthorities)
                log.debug("User Details ${userDetails.toString()}")
                return userDetails
            } else {
                throw new InstantiationException('could not instantiate new user')
            }
        }
    }

    protected String getSamlUsername(credential) {
        log.debug("getSamlUsername")
        if (samlUserAttributeMappings?.username) {
            def value = credential.getAttributeAsString(samlUserAttributeMappings.username)
            log.debug("Username getSamlUsername ${value}")
            return value
        } else {
            // if no mapping provided for username attribute then assume it is the returned subject in the assertion
            return credential.nameID?.value
        }
    }

    protected Object mapAdditionalAttributes(SAMLCredential credential, user) {
        samlUserAttributeMappings.each { key, value ->
            def samlValue = credential.getAttributeAsString(value)
            if (samlValue) {
                user."$key" = samlValue
            }
        }
        user
    }

    protected Collection<GrantedAuthority> getAuthoritiesForUser(SAMLCredential credential, String username) {
        Set<GrantedAuthority> authorities = new HashSet<SimpleGrantedAuthority>()

        String[] samlGroups = credential.getAttributeAsStringArray(samlUserGroupAttribute)

        samlGroups.eachWithIndex { groupName, groupIdx ->
            log.debug("Group Name From Saml ${groupName}")
            def role = samlUserGroupToRoleMapping?.find{ it?.value == groupName }?.key
            def authority
            if (role){
                log.debug("Found Role")
                authority = getRole(role)
            }
            if (authority) {
                log.debug("Found Authority Adding it")
                authorities.add(new SimpleGrantedAuthority(authority."$authorityNameField"))
            }
        }
        log.debug("Returning Authorities with  ${authorities?.size()} Authorities Added")
        return authorities
    }


    private Object generateSecurityUser(username) {

        if (userDomainClassName) {
            log.debug("UserClassName ${userDomainClassName}")
            Class<?> UserClass = grailsApplication.getClassForName(userDomainClassName)
            log.debug("Artefact ${grailsApplication.getClassForName(userDomainClassName)}")
            log.debug("Config ${grailsApplication.config.toString()}")

                    //getClassForName(userDomainClassName)?.clazz
            log.debug("UserClass ${UserClass}")
            if (UserClass) {
                def user = BeanUtils.instantiateClass(UserClass)
                user.username = username
                user.password = "password"
                return user
            } else {
                throw new ClassNotFoundException("domain class ${userDomainClassName} not found")
            }
        } else {
            throw new ClassNotFoundException("security user domain class undefined")
        }
    }

    private def saveUser(userClazz, user, authorities) {
        log.debug("Saving User")
        if (userClazz && samlAutoCreateActive && samlAutoCreateKey && authorityNameField && authorityJoinClassName) {

            Map whereClause = [:]
            whereClause.put "$samlAutoCreateKey".toString(), user."$samlAutoCreateKey"
            Class<?> joinClass = grailsApplication.getDomainClass(authorityJoinClassName)?.clazz
            log.debug("Before With Transaction")

                log.debug("Saving User")
                def existingUser
                userClazz.withTransaction {
                    existingUser = userClazz.findWhere(whereClause)
                }

                if (!existingUser) {
                    log.debug("User Doesn't Exist.....save it")
                    userClazz.withTransaction {
                        user.save(flush:true)
                        //if (!user.save()) throw new UsernameNotFoundException("Could not save user ${user}");
                    }

                } else {
                    log.debug("User Exists.....update its properties")
                    user = updateUserProperties(existingUser, user)

                    if (samlAutoAssignAuthorities) {
                        log.debug("Remove all Authorities")
                        joinClass.withTransaction {
                            joinClass.removeAll user
                        }


                    }
                    log.debug("Now Save the User")
                    userClazz.withTransaction {
                        user.save()
                    }

                }

                if (samlAutoAssignAuthorities) {
                    log.debug("go thru the list of authorities")
                    authorities.each { grantedAuthority ->
                        log.debug("Working on Authority ${grantedAuthority}.${authorityNameField}")
                        def role = getRole(grantedAuthority."${authorityNameField}")
                        log.debug("SAVING USER_ROLE - User name ${user.username}")
                        log.debug("SAVING USER_ROLE - Role name ${role.authority}")
                        log.debug("SAVING USER_ROLE - User Id ${user.id}")
                        log.debug("SAVING USER_ROLE - Role Id ${role.id}")
                        joinClass.withTransaction {
                            if (!joinClass.exists(user.id, role.id)){
                                joinClass.create(user, role, true)
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
            log.debug("getRole - param -> ${authority}")
            Class<?> RoleClass = grailsApplication.getDomainClass(authorityClassName).clazz
            Map whereClause = [:]
            whereClause.put "$authorityNameField".toString(), authority
            if (RoleClass) {
                RoleClass.withTransaction {
                    log.debug("Where clause -> ${whereClause}")
                    def returnVal = RoleClass.findWhere(whereClause)
                    log.debug("Return Value from getRole Class-> ${returnVal?.class}  Value -> ${returnVal}")
                    returnVal
                }
            } else {
                throw new ClassNotFoundException("domain class ${authorityClassName} not found")
            }
        }
    }
}
