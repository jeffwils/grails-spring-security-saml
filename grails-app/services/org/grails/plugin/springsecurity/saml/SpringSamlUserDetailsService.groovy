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
import org.springframework.beans.BeanUtils
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.saml.SAMLCredential
import org.springframework.security.saml.userdetails.SAMLUserDetailsService

/**
 * A {@link GormUserDetailsService} extension to read attributes from a LDAP-backed
 * SAML identity provider. It also reads roles from database
 *
 * @author alvaro.sanchez
 */
@Transactional
@Slf4j('logger')
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
        logger.debug("Loading user - ${credential.toString()}")
        if (credential) {
            String username = getSamlUsername(credential)
            logger.debug("Username ${username}")
            if (!username) {
                throw new UsernameNotFoundException("No username supplied in saml response.")
            }

            def user = generateSecurityUser(username)
            logger.debug("Generated User ${user.username}")
            user = mapAdditionalAttributes(credential, user)
            if (user) {
                logger.debug "Loading database roles for $username..."
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
                logger.debug("User Class ${user?.class}")
                logger.debug("User - username ${user?.username}")
                logger.debug("User - id ${user?.id}")
                def userDetails = createUserDetails(user, grantedAuthorities)
                logger.debug("User Details ${userDetails.toString()}")
                return userDetails
            } else {
                throw new InstantiationException('could not instantiate new user')
            }
        }
    }

    protected String getSamlUsername(credential) {
        logger.debug("getSamlUsername()")
        def usernameAttr = samlUserAttributeMappings?.username
        if ( usernameAttr ) {
            def value = credential.getAttributeAsString(usernameAttr)
            logger.debug("Username using attribute '${usernameAttr}': ${value}")
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

        logger.debug( 'Using samlUserGroupAttribute: ' + samlUserGroupAttribute)
        String[] samlGroups = credential.getAttributeAsStringArray(samlUserGroupAttribute)
        logger.debug( 'Using samlGroups: ' + samlGroups )
        logger.debug( 'User samlUserGroupToRoleMapping: ' + samlUserGroupToRoleMapping )

        samlGroups.eachWithIndex { groupName, groupIdx ->
            logger.debug("Group Name From SAML: ${groupName}")
            def role = samlUserGroupToRoleMapping?.find{ it?.value == groupName }?.key
            def authority
            if (role){
                logger.debug("Found Role")
                authority = getRole(role)
            }
            if (authority) {
                logger.debug("Found Authority Adding it")
                authorities.add(new SimpleGrantedAuthority(authority."$authorityNameField"))
            }
        }
        logger.debug("Returning Authorities with  ${authorities?.size()} Authorities Added")
        return authorities
    }


    private Object generateSecurityUser(username) {

        if (userDomainClassName) {
            logger.debug("UserClassName ${userDomainClassName}")
            Class<?> UserClass = grailsApplication.getClassForName(userDomainClassName)
            logger.debug("Artefact ${grailsApplication.getClassForName(userDomainClassName)}")
            logger.debug("Config ${grailsApplication.config.toString()}")

                    //getClassForName(userDomainClassName)?.clazz
            logger.debug("UserClass ${UserClass}")
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
}
