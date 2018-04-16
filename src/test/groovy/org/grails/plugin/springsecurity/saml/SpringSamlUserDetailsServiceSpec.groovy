package org.grails.plugin.springsecurity.saml

import grails.plugin.springsecurity.userdetails.GrailsUser
import grails.testing.gorm.DataTest
import grails.testing.services.ServiceUnitTest
import org.opensaml.saml2.core.NameID
import org.opensaml.saml2.core.Assertion
import org.opensaml.saml2.core.impl.AssertionImpl
import org.opensaml.saml2.core.impl.NameIDImpl
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.saml.SAMLCredential
import spock.lang.Ignore
import spock.lang.Specification
import test.TestRole
import test.TestSamlUser
import test.TestUserRole

import static UnitTestUtils.*

class SpringSamlUserDetailsServiceSpec  extends Specification implements ServiceUnitTest<SpringSamlUserDetailsService>, DataTest {
    SAMLCredential credential
    NameID nameID
    Assertion assertion
    TestRole testRole, testRole2

    String username = "jackSparrow"

    void setup() {
        mockDomains( TestSamlUser, TestRole, TestUserRole )
        mockOutDefaultGrailsApplication()

        mockOutSpringSecurityUtilsConfig()
        mockWithTransaction()

        service.authorityClassName = ROLE_CLASS_NAME
        service.authorityJoinClassName = JOIN_CLASS_NAME
        service.authorityNameField = "authority"
        service.samlAutoCreateActive = false
        service.samlAutoCreateKey = null
        service.samlUserAttributeMappings = [username: USERNAME_ATTR_NAME]
        service.samlUserGroupAttribute = GROUP_ATTR_NAME
        service.samlUserGroupToRoleMapping = ["$ROLE": 'myGroup']
        service.userDomainClassName = USER_CLASS_NAME
        service.grailsApplication = grailsApplication

        nameID = new NameIDImpl("", "", "")
        assertion = new AssertionImpl("", "", "")

        // This is what a SamlResponse will eventually be marshalled to
        credential = new SAMLCredential(nameID, assertion, null, null)
        credential.metaClass.getNameID = { [value: "$username"] }

        testRole = new TestRole(authority: ROLE)
        testRole2 = new TestRole(authority: "FAKEROLE2")

        // set default username to be returned in the saml response
        setMockSamlAttributes(credential, ["$USERNAME_ATTR_NAME": username])
    }

    void cleanup() {
        // Reset back the methods
        TestUserRole.metaClass.'static'.removeAll = { TestSamlUser userWithRoles ->
            executeUpdate "DELETE FROM TestUserRole WHERE user=:user", [user: userWithRoles]
        }
        TestUserRole.metaClass.'static'.create = { TestSamlUser userWithNoRoles, TestRole role ->
            new TestUserRole(user: userWithNoRoles, role: role).save(flush: false, insert: true)
        }
    }

    void "loadUserBySAML should return a GrailsUser"() {
        given:
            def user = service.loadUserBySAML(credential)

        expect:
            user instanceof GrailsUser
    }

    void "loadUserBySAML should return NameID as the username when no mapping specified"() {
        given:
            service.samlUserAttributeMappings = [:]
            setMockSamlAttributes(credential, ["$USERNAME_ATTR_NAME": "someotherValue"])
            def user = service.loadUserBySAML(credential)

        expect:
            user.username == username
    }

    void "loadUserBySAML should set username from the mapped saml attribute"() {
        given:
            def user = service.loadUserBySAML(credential)

        expect:
            user.username == username
    }

    void "loadUserBySAML should raise an exception if username not supplied in saml response"() {
        when:
            setMockSamlAttributes(credential, ["$USERNAME_ATTR_NAME": null])
            def user = service.loadUserBySAML(credential)

        then:
            def e = thrown( UsernameNotFoundException )
            e.message == "No username supplied in saml response."
    }

    void "loadUserBySAML should return a user with the mapped role"() {
        given:
            testRole.save( failOnError: true )
            setMockSamlAttributes(credential,
                    ["$GROUP_ATTR_NAME": "myGroup",
                     "$USERNAME_ATTR_NAME": 'myUsername'])
            def user = service.loadUserBySAML(credential)

        expect:
            user.authorities.size() == 1
            user.authorities.toArray()[0].authority == ROLE
    }

    void "loadUserBySAML should not persist the user if autocreate is not active"() {
        when:
            service.loadUserBySAML(credential)

        then:
            old( TestSamlUser.count() ) == TestSamlUser.count()
    }

    void "loadUserBySAML should persist the user when autocreate is active"() {
        given:
            service.samlAutoCreateActive = true
            service.samlAutoCreateKey = 'username'

        when:
            def userDetails = service.loadUserBySAML(credential)

        then:
            TestSamlUser.count() == old( TestSamlUser.count() ) + 1
            TestSamlUser.findByUsername(userDetails.username)
    }

    void "loadUserBySAML should set additional mapped attributes on the user"() {
        given:
            def emailAddress = "test@mailinator.com"
            def firstname = "Jack"
            service.samlAutoCreateActive = true
            service.samlAutoCreateKey = 'username'

            service.samlUserAttributeMappings = [email: "$MAIL_ATTR_NAME", firstName: "$FIRSTNAME_ATTR_NAME"]
            setMockSamlAttributes(credential, ["$USERNAME_ATTR_NAME": username, "$MAIL_ATTR_NAME": emailAddress, "$FIRSTNAME_ATTR_NAME": firstname])

        when:
            def user = service.loadUserBySAML(credential)
            def samlUser = TestSamlUser.findByUsername(username)

        then:
            samlUser.email == emailAddress
            samlUser.firstName == firstname
    }


    void "loadUserBySAML should not persist a user that already exists"() {
        given:
            service.samlAutoCreateActive = true
            service.samlAutoCreateKey = 'username'

            def user = new TestSamlUser(username: username, password: 'test')
            user.save( failOnError: true )

            TestUserRole.metaClass.'static'.removeAll = { TestSamlUser userWithRoles -> }

        when:
            def userDetail = service.loadUserBySAML(credential)

        then:
            old( TestSamlUser.count() ) == TestSamlUser.count()
    }

    @Ignore( 'This path in SpringSamlUserDetailsService seems to have been commented out in the Grails 3.0 migration.')
    void "loadUserBySAML should raise valid exception for users in invalid states"() {
        given:
            def sharedEmail = "some.user@gmail.com"
            // email should be unique but we are going to try and save a user whose username has changed but email has not.
            def oldAccount = new TestSamlUser(username: "someUser", password: 'test', email: sharedEmail).save()

            service.samlAutoCreateActive = true
            service.samlAutoCreateKey = 'username'
            service.samlUserAttributeMappings = [email: "$MAIL_ATTR_NAME"]
            setMockSamlAttributes(credential, ["$USERNAME_ATTR_NAME": username, "$MAIL_ATTR_NAME": sharedEmail])

        when:
            service.loadUserBySAML(credential)

        then:
            thrown( UsernameNotFoundException )
    }

    void "loadUserBySAML should persist the role for a new user"() {
        given:
            testRole.save( failOnError: true )
            service.samlAutoCreateActive = true
            service.samlAutoCreateKey = 'username'
            setMockSamlAttributes(credential, ["$GROUP_ATTR_NAME": "something=something,CN=myGroup", "$USERNAME_ATTR_NAME": username])

            TestUserRole.metaClass.'static'.removeAll = { TestSamlUser userWithRoles ->
                // no roles to remove
                assert false
            }
            TestUserRole.metaClass.'static'.create = { TestSamlUser userWithNoRoles, TestRole role ->
                assert userWithNoRoles.username == username
                assert role.authority == ROLE
            }

        expect:
            def userDetail = service.loadUserBySAML(credential)
    }

    void "loadUserBySAML should update the roles for an existing user"() {
        given:
            service.samlAutoCreateActive = true
            service.samlAutoCreateKey = 'username'
            setMockSamlAttributes(credential, ["$GROUP_ATTR_NAME": "myGroup", "$USERNAME_ATTR_NAME": username])

            testRole.save( failOnError: true )
            def user = new TestSamlUser(username: username, password: 'test')
            user.save( failOnError: true )

            def removedExistingRoles = false
            TestUserRole.metaClass.'static'.removeAll = { TestSamlUser userWithRoles ->
                assert userWithRoles.username == user.username
                removedExistingRoles = true
            }

            def savedNewRoles = false
            TestUserRole.metaClass.'static'.create = { TestSamlUser userWithNoRoles, TestRole role, boolean flush ->
                assert userWithNoRoles.username == user.username
                assert role.authority == ROLE
                savedNewRoles = true
            }

        when:
            def userDetail = service.loadUserBySAML(credential)

        then:
            removedExistingRoles
            savedNewRoles
    }

    void "loadUserBySAML should  not update the roles for an existing user"() {
        given:
            service.samlAutoCreateActive = true
            service.samlAutoAssignAuthorities = false
            service.samlAutoCreateKey = 'username'

            setMockSamlAttributes(credential, ["$GROUP_ATTR_NAME": "something=something,CN=myGroup", "$USERNAME_ATTR_NAME": username])

            testRole.save( failOnError: true )
            def user = new TestSamlUser(username: username, password: 'test')
            user.save( failOnError: true )

            def removedExistingRoles = false
            TestUserRole.metaClass.'static'.removeAll = { TestSamlUser userWithRoles ->
                assert userWithRoles.username == user.username
                removedExistingRoles = true
            }

            def savedNewRoles = false
            TestUserRole.metaClass.'static'.create = { TestSamlUser userWithNoRoles, TestRole role ->
                assert userWithNoRoles.username == user.username
                assert role.authority == ROLE
                savedNewRoles = true
            }

        when:
            def userDetail = service.loadUserBySAML(credential)

        then:
            !removedExistingRoles
            !savedNewRoles
    }

    void "loadUserBySAML should still pull details from DB"() {
        given:
            service.samlAutoCreateActive = true
            service.samlAutoAssignAuthorities = false
            service.samlAutoCreateKey = 'username'

            setMockSamlAttributes(credential, ["$GROUP_ATTR_NAME": "something=something,CN=myGroup", "$USERNAME_ATTR_NAME": username])

            testRole.save( failOnError: true )
            testRole2.save( failOnError: true )
            def user = new TestSamlUser(username: username, password: 'test')
            user.save( failOnError: true )

            TestUserRole.create(user,testRole2)

            // Mocking
            def removedExistingRoles = false
            TestUserRole.metaClass.'static'.removeAll = { TestSamlUser userWithRoles ->
                assert userWithRoles.username == user.username
                removedExistingRoles = true
            }

            def savedNewRoles = false
            TestUserRole.metaClass.'static'.create = { TestSamlUser userWithNoRoles, TestRole role ->
                assert userWithNoRoles.username == user.username
                assert role.authority == ROLE
                savedNewRoles = true
            }

        when:
            def userDetail = service.loadUserBySAML(credential)
            Set authorities = userDetail.getAuthorities()

        then:
            !removedExistingRoles
            !savedNewRoles
            authorities.size() == 1
            authorities.iterator().next().authority == testRole2.authority
    }

    void "loadUserBySAML should set any mapped fields for a user"() {
        given:
            def emailAddress = "test@mailinator.com"
            def firstname = "Jack"

            service.samlAutoCreateActive = true
            service.samlAutoCreateKey = 'username'
            service.samlUserAttributeMappings = [email: "$MAIL_ATTR_NAME", firstName: "$FIRSTNAME_ATTR_NAME"]
            setMockSamlAttributes(credential, ["$USERNAME_ATTR_NAME": username, "$MAIL_ATTR_NAME": emailAddress, "$FIRSTNAME_ATTR_NAME": firstname])

            def user = new TestSamlUser(username: username, password: 'test')
            user.save( failOnError: true )

            TestUserRole.metaClass.'static'.removeAll = {TestSamlUser samlUser -> }

        when:
            service.loadUserBySAML(credential)
            def updatedUser = TestSamlUser.findByUsername(username)

        then:
            updatedUser.email == emailAddress
            updatedUser.firstName == firstname
    }

    void "loadUserBySAML should update mapped fields for a user"() {
        given:
            def intialEmail = 'myfirstmail@mailinator.com'
            def emailAddress = "test@mailinator.com"

            service.samlAutoCreateActive = true
            service.samlAutoCreateKey = 'username'
            service.samlUserAttributeMappings = [email: "$MAIL_ATTR_NAME"]
            setMockSamlAttributes(credential, ["$USERNAME_ATTR_NAME": username, "$MAIL_ATTR_NAME": emailAddress])
            TestUserRole.metaClass.'static'.removeAll = {TestSamlUser samlUser -> }

            def user = new TestSamlUser(username: username, password: 'test', email: intialEmail)
            user.save( failOnError: true )

        when:
            service.loadUserBySAML(credential)
            def updatedUser = TestSamlUser.findByUsername(username)

        then:
            updatedUser.email == emailAddress
    }
}
