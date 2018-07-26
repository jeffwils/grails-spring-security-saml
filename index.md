{% include_relative README.md %}

### Configuration
The Plugin basically creates a bridge from your application configuration to both the Spring Security SAML Plugin and the Grails Spring Security Plugin.  Instead of having to map all of the beans in your application, the plugin wires the SAML Plugin beans from your application configuration.

All configuration items are preceeded with grails >> plugin >> springsecurity >> saml.  The following is a list of all of the configuration options available.

#### Spring Security Starter
The spring security starter must be added to your build.gradle

```
compile "org.springframework.boot:spring-boot-starter-security"
```

#### Spring Security Classes
The plugin requires that the Spring Security Classes that are created with the s2-quickstart, are present in your application.
To run s2-quickstart, see [s2-quickstart](https://grails-plugins.github.io/grails-spring-security-core/v3/#s2-quickstart)

Command Line Example

```
$> grails s2-quickstart com.jeffwils UserAcct Role
```

This will create the Spring Security Domain Classes and it will create/modify the application.groovy file. You can convert the generated configuration to yaml format and use it in application.yml as well.

Warning: Some table or column names may conflict with existing SQL keywords such as 'USER' or 'PASSWORD' on postgres or other RDBMS. If neccessary these can be adjusted in the mapping block of your user domain class:

```
static mapping = {
    table 'users'
    password column: '`password`'
}
```

#### Authentication Provider
The plugin sets up a SAML Authentication provider **samlAuthenticationProvider** which can be referenced in the Grails Spring Security Plugin configuration

```yaml
grails:
   plugins:
      springsecurity:
         providerNames: ['samlAuthenticationProvider', ......]
```

#### Property Table

All of these properties can be put in either `application.yml` or `application.groovy` and they are all prefixed with:
**grails.plugins.springsecurity.saml**


| Property | Syntax | Example Value | Description |
|--------|------|-------------|-----------|
| active | boolean | true | States whether or not SAML is active |
| afterLoginUrl | url string | '/' | Redirection Url in your application upon successful login from the IDP |
| afterLogoutUrl | url string | '/' | Redirection Url in your application upon successful logout from the IDP |
| responseSkew | numeric | 60 | Time in seconds to account for differences in clock time between SP and IDP if their times should differ when attempting to compare request and assertion time index values  |
| signatureAlgorithm | String Value | 'rsa-sha256' | Accepted Values are From org.opensaml.xml.signature.SignatureConstants |
| digestAlgorithm | String Value | 'sha256' | Accepted Values are From org.opensaml.xml.encryption.EncryptionConstants |
| userAttributeMappings | Map | [username:'funkyUserNameFromIDP'] | Allows Custom Mapping if both Application and IDP Attribute Names cannot be changed. |
| userGroupAttribute | String Value | 'memberOf' | Corresponds to the Role Designator in the SAML Assertion from the IDP |
| userGroupToRoleMapping | Map [Spring Security Role: Saml Assertion Role] | [ROLE_MY_APP_ROLE: 'CN=MYSAMLGROUP, OU=MyAppGroups, DC=myldap, DC=example, DC=com'] | This maps the Spring Security Roles in your application to the roles from the SAML Assertion.  Only roles in this Map will be resolved. |
| useLocalRoles | boolean | true | Determine a user's role based on the existing values in the local Spring Security tables. Will merge with additional roles loaded via `userGroupAttribute` and `userGroupToRoleMapping`. Defaults to `false`.
| autoCreate.active | boolean | false | If you want the plugin to generate users in the DB as they are authenticated via SAML
| autoCreate.key | domain class unique identifier | 'id' | if autoCreate active is true then this is the unique id field of the db table |
| autoCreate.assignAuthorities | boolean | false | If you want the plugin to insert the authorities that come from the SAML message into the UserRole Table. |
| metadata.providers | Map [idp alias: idp file reference] | [ping:"/pathtoIdpFile/myIdp.xml"] | Map of idp providers. Contain an alias and reference to the idp xml file |
| metadata.defaultIdp | String | 'https://idp.example.org/idp/shibboleth' | the entityId of the default Idp from the ones listed in the metadata.provider map. If no entityId is given an IDP will be picked from the list automatically. |
| metadata.url | relative url | '/saml/metadata' | url used to retrieve the SP metadata for your app to send to the IDP |
| metadata.sp.file | file reference as string | "/mySpFilePath/myspfile.xml" | Reference to your SP XML File.  This can be on the classpath or in your file system. |
| metadata.sp.defaults.local | boolean | true | True for metadata of a local service provider. False for remote identity providers. |
| metadata.sp.defaults.entityId | String Value |'http://myapp.example.com' | Identifier for the Service Provider |
| metadata.sp.defaults.alias | url alias | 'myalias' | Unique alias used to identify the selected local service provider based on used URL.  Will be postpended to the url in the SP File generated and given to the IDP |
| metadata.sp.defaults.securityProfile | String Value | 'pkix' | Security profile for verification of message signatures metaiop, pkix |
| metadata.sp.defaults.signingKey | keystore alias | 'mykey' | For local entities alias of private key used to create signatures. The default private key is used when no value is provided. For remote identity providers defines an additional public key used to verify signatures. |
| metadata.sp.defaults.encryptionKey | keystore alias | 'mykey' | For local entities alias of private key used to encrypt data. The default private key is used when no value is provided. For remote identity providers defines an additional public key used to decrypt data. |
| metadata.sp.defaults.tlsKey | keystore alias | 'mykey' | For local entities alias of private key used for SSL/TLS client authentication. No client authentication is used when value is not specified. For remote identity providers defines an additional public key used for trust resolution. |
| metadata.sp.defaults.requireArtifactResolveSigned | boolean | false | Enables signing of artifact resolution requests sent to the remote identity providers. |
| metadata.sp.defaults.requireLogoutRequestSigned | boolean | false | For local entities enables requirement of signed logout requests. For remote entities enables signing of requests sent to the IDP. |
| metadata.sp.defaults.requireLogoutResponseSigned | boolean | false | For local entities enables requirement of signed logout responses. For remote entities enables signing of responses sent to the IDP. |
| keyManager.storeFile | file reference string |  "/mypath/mykeystore.jks" |
| keyManager.storePass | password string | 'changeit' | Keypass to keystore referenced in storeFile |
| keyManager.passwords | password map [private key alias:password] | [mykey:'changeit'] | Map of aliases and passwords if private key in storeFile is password protected |
| keyManager.defaultKey | keystore alias | 'mykey' | Default Key Alias in keystore referenced in storeFile |

#### Example Configuration

The following are example configurations that will allow the application to start up correctly out of the box and have all the required beans mapped.  There are two build.gradle files (3.0.9 which should cover all 3.0.x and 3.2.8 which should work with 3.1+).  The example configurations (application.groovy & application.yml) utilize some of the defaults in the plugin and will need to be changed in your application (The SP and IDP specific) settings so that it will work with your service provider/identity provider configuration.

build.gradle grails 3.0.9

```
buildscript {
    ext {
        grailsVersion = project.grailsVersion
    }
    repositories {
        mavenLocal()
        maven { url "https://repo.grails.org/grails/core" }
    }
    dependencies {        
        classpath "org.grails:grails-gradle-plugin:$grailsVersion"
        classpath 'com.bertramlabs.plugins:asset-pipeline-gradle:2.5.0'
        classpath "org.grails.plugins:hibernate:4.3.10.5"
    }
}

plugins {
    id "io.spring.dependency-management" version "0.5.2.RELEASE"
}

version "0.1"
group "ss.test"

apply plugin: "spring-boot"
apply plugin: "war"
apply plugin: "asset-pipeline"
apply plugin: 'eclipse'
apply plugin: 'idea'
apply plugin: "org.grails.grails-web"
apply plugin: "org.grails.grails-gsp"

ext {
    grailsVersion = project.grailsVersion
    gradleWrapperVersion = project.gradleWrapperVersion
}

assets {
    minifyJs = true
    minifyCss = true
}

repositories {
    mavenLocal()
    mavenCentral()
    maven { url "https://repo.grails.org/grails/core" }
    maven { url "http://central.maven.org/maven2/"}
    maven { url "https://build.shibboleth.net/nexus/content/repositories/releases"}
    maven { url "https://build.shibboleth.net/nexus/content/groups/public/"}
    maven { url "https://code.lds.org/nexus/content/groups/main-repo"}
    maven { url "http://repository.jboss.org/maven2/"}
}

dependencyManagement {
    imports {
        mavenBom "org.grails:grails-bom:$grailsVersion"
    }
    applyMavenExclusions false
}

dependencies {
    compile "org.springframework.boot:spring-boot-starter-logging"
    compile "org.springframework.boot:spring-boot-starter-actuator"
    compile "org.springframework.boot:spring-boot-autoconfigure"
    compile "org.springframework.boot:spring-boot-starter-tomcat"
    compile "org.springframework.boot:spring-boot-starter-security"
    compile "org.grails:grails-dependencies"
    compile "org.grails:grails-web-boot"

    compile "org.grails.plugins:hibernate"
    compile "org.grails.plugins:cache"
    compile "org.hibernate:hibernate-ehcache"
    compile "org.grails.plugins:scaffolding"
    compile 'org.grails.plugins:spring-security-core:3.1.1'
    compile "org.grails.plugins:spring-security-saml:3.0.0"

    runtime "org.grails.plugins:asset-pipeline"

    testCompile "org.grails:grails-plugin-testing"
    testCompile "org.grails.plugins:geb"

    // Note: It is recommended to update to a more robust driver (Chrome, Firefox etc.)
    testRuntime 'org.seleniumhq.selenium:selenium-htmlunit-driver:2.44.0'

    console "org.grails:grails-console"
}

task wrapper(type: Wrapper) {
    gradleVersion = gradleWrapperVersion
}
```

build.gradle 3.2.8

```
buildscript {
    repositories {
        mavenLocal()
        maven { url "https://repo.grails.org/grails/core" }
    }
    dependencies {
        classpath "org.grails:grails-gradle-plugin:$grailsVersion"
        classpath "com.bertramlabs.plugins:asset-pipeline-gradle:2.14.1"
        classpath "org.grails.plugins:hibernate5:${gormVersion-".RELEASE"}"
    }
}

version "0.1"
group "ss.test.latest"

apply plugin:"eclipse"
apply plugin:"idea"
apply plugin:"war"
apply plugin:"org.grails.grails-web"
apply plugin:"org.grails.grails-gsp"
apply plugin:"asset-pipeline"

repositories {
    mavenLocal()
    maven { url "https://repo.grails.org/grails/core" }
    maven { url "http://central.maven.org/maven2/"}
    maven { url "https://build.shibboleth.net/nexus/content/repositories/releases"}
    maven { url "https://build.shibboleth.net/nexus/content/groups/public/"}
    maven { url "https://code.lds.org/nexus/content/groups/main-repo"}
    maven { url "http://repository.jboss.org/maven2/"}
}

dependencies {
    compile "org.springframework.boot:spring-boot-starter-logging"
    compile "org.springframework.boot:spring-boot-autoconfigure"
    compile "org.grails:grails-core"
    compile "org.springframework.boot:spring-boot-starter-actuator"
    compile "org.springframework.boot:spring-boot-starter-tomcat"
    compile "org.springframework.boot:spring-boot-starter-security"
    compile "org.grails:grails-dependencies"
    compile "org.grails:grails-web-boot"
    compile "org.grails.plugins:cache"
    compile "org.grails.plugins:scaffolding"
    compile "org.grails.plugins:hibernate5"
    compile "org.hibernate:hibernate-core:5.1.3.Final"
    compile "org.hibernate:hibernate-ehcache:5.1.3.Final"
    compile 'org.grails.plugins:spring-security-core:3.1.1'
    compile "org.grails.plugins:spring-security-saml:3.0.0"
    console "org.grails:grails-console"
    profile "org.grails.profiles:web"
    runtime "com.bertramlabs.plugins:asset-pipeline-grails:2.14.1"
    runtime "com.h2database:h2"
    testCompile "org.grails:grails-plugin-testing"
    testCompile "org.grails.plugins:geb"
    testRuntime "org.seleniumhq.selenium:selenium-htmlunit-driver:2.47.1"
    testRuntime "net.sourceforge.htmlunit:htmlunit:2.18"
}

bootRun {
    jvmArgs('-Dspring.output.ansi.enabled=always')
    addResources = true
}


assets {
    minifyJs = true
    minifyCss = true
}
```

application.groovy

```
// Added by the Spring Security Core plugin:
grails.plugin.springsecurity.userLookup.userDomainClassName = 'com.jeffwils.User'
grails.plugin.springsecurity.userLookup.authorityJoinClassName = 'com.jeffwils.UserRole'
grails.plugin.springsecurity.authority.className = 'com.jeffwils.Role'
grails.plugin.springsecurity.requestMap.className = 'com.jeffwils.UserRole'
grails.plugin.springsecurity.securityConfigType = 'Requestmap'
grails.plugin.springsecurity.controllerAnnotations.staticRules = [
	[pattern: '/',               access: ['permitAll']],
	[pattern: '/error',          access: ['permitAll']],
	[pattern: '/index',          access: ['permitAll']],
	[pattern: '/index.gsp',      access: ['permitAll']],
	[pattern: '/shutdown',       access: ['permitAll']],
	[pattern: '/assets/**',      access: ['permitAll']],
	[pattern: '/**/js/**',       access: ['permitAll']],
	[pattern: '/**/css/**',      access: ['permitAll']],
	[pattern: '/**/images/**',   access: ['permitAll']],
	[pattern: '/**/favicon.ico', access: ['permitAll']]
]

grails.plugin.springsecurity.filterChain.chainMap = [
	[pattern: '/assets/**',      filters: 'none'],
	[pattern: '/**/js/**',       filters: 'none'],
	[pattern: '/**/css/**',      filters: 'none'],
	[pattern: '/**/images/**',   filters: 'none'],
	[pattern: '/**/favicon.ico', filters: 'none'],
	[pattern: '/**',             filters: 'JOINED_FILTERS']
]

grails.plugin.springsecurity.providerNames = ['samlAuthenticationProvider', 'daoAuthenticationProvider', 'anonymousAuthenticationProvider']

grails.plugin.springsecurity.saml.active = true
grails.plugin.springsecurity.saml.afterLoginUrl = '/'
grails.plugin.springsecurity.saml.afterLogoutUrl = '/'
grails.plugin.springsecurity.saml.responseSkew = 300
grails.plugin.springsecurity.saml.signatureAlgorithm = 'rsa-sha256'
grails.plugin.springsecurity.saml.digestAlgorithm = 'sha256'
grails.plugin.springsecurity.saml.userGroupAttribute = 'roles'
grails.plugin.springsecurity.saml.autoCreate.active = false  //If you want the plugin to generate users in the DB as they are authenticated via SAML
grails.plugin.springsecurity.saml.autoCreate.key = 'id'
grails.plugin.springsecurity.saml.autoCreate.assignAuthorities=false  //If you want the plugin to assign the authorities that come from the SAML message.
grails.plugin.springsecurity.saml.metadata.defaultIdp = 'localhost:default:entityId'
grails.plugin.springsecurity.saml.metadata.url = '/saml/metadata'
grails.plugin.springsecurity.saml.metadata.providers = [ping:'security/idp-local.xml']
grails.plugin.springsecurity.saml.metadata.sp.file = "security/sp.xml"
grails.plugin.springsecurity.saml.metadata.sp.defaults.local = true;
grails.plugin.springsecurity.saml.metadata.sp.defaults.entityId = 'test'
grails.plugin.springsecurity.saml.metadata.sp.defaults.alias = 'test';
grails.plugin.springsecurity.saml.metadata.sp.defaults.securityProfile = 'pkix';
grails.plugin.springsecurity.saml.metadata.sp.defaults.signingKey = 'ping';
grails.plugin.springsecurity.saml.metadata.sp.defaults.encryptionKey = 'ping';
grails.plugin.springsecurity.saml.metadata.sp.defaults.tlsKey = 'ping';
grails.plugin.springsecurity.saml.metadata.sp.defaults.requireArtifactResolveSigned = false;
grails.plugin.springsecurity.saml.metadata.sp.defaults.requireLogoutRequestSigned = false;
grails.plugin.springsecurity.saml.metadata.sp.defaults.requireLogoutResponseSigned = false;
grails.plugin.springsecurity.saml.keyManager.storeFile = "classpath:security/keystore.jks"
grails.plugin.springsecurity.saml.keyManager.storePass = 'nalle123'
grails.plugin.springsecurity.saml.keyManager.passwords = ping:'ping123'
grails.plugin.springsecurity.saml.keyManager.defaultKey = 'ping'
```

application.yml

```
grails:
   plugin:
      springsecurity:
         userLookup:
            userDomainClassName: 'com.jeffwils.User'
            authorityJoinClassName: 'com.jeffwils.UserRole'
         authority:
            className: 'com.jeffwils.Role'
         requestMap:
            className: 'com.jeffwils.UserRole'
         securityConfigType: 'Requestmap'
         controllerAnnotations:
            staticRules: [
                          	[pattern: '/',               access: ['permitAll']],
                          	[pattern: '/error',          access: ['permitAll']],
                          	[pattern: '/index',          access: ['permitAll']],
                          	[pattern: '/index.gsp',      access: ['permitAll']],
                          	[pattern: '/shutdown',       access: ['permitAll']],
                          	[pattern: '/assets/**',      access: ['permitAll']],
                          	[pattern: '/**/js/**',       access: ['permitAll']],
                          	[pattern: '/**/css/**',      access: ['permitAll']],
                          	[pattern: '/**/images/**',   access: ['permitAll']],
                          	[pattern: '/**/favicon.ico', access: ['permitAll']]
                          ]
         filterChain:
            chainMap: [
                        	[pattern: '/assets/**',      filters: 'none'],
                        	[pattern: '/**/js/**',       filters: 'none'],
                        	[pattern: '/**/css/**',      filters: 'none'],
                        	[pattern: '/**/images/**',   filters: 'none'],
                        	[pattern: '/**/favicon.ico', filters: 'none'],
                        	[pattern: '/**',             filters: 'JOINED_FILTERS']
                      ]
         providerNames: ['samlAuthenticationProvider', 'daoAuthenticationProvider', 'anonymousAuthenticationProvider']

         saml:
            active: true
            afterLoginUrl: '/'
            afterLogoutUrl: '/'
            responseSkew: 300
            signatureAlgorithm = 'rsa-sha256'
            digestAlgorithm = 'sha256'
            userGroupAttribute = 'roles'
            autoCreate:
               active: false  //If you want the plugin to generate users in the DB as they are authenticated via SAML
               key: 'id'
               assignAuthorities: false  //If you want the plugin to assign the authorities that come from the SAML message.
            metadata:
               defaultIdp: 'localhost:default:entityId'
               url: '/saml/metadata'
               providers: [ping:'security/idp-local.xml']
               sp:
                  file: "security/sp.xml"
                  defaults:
                     local: true
                     entityId: 'test'
                     alias: 'test'
                     securityProfile: 'pkix';
                     signingKey: 'ping'
                     encryptionKey: 'ping'
                     tlsKey: 'ping'
                     requireArtifactResolveSigned: false
                     requireLogoutRequestSigned: false
                     requireLogoutResponseSigned: false
            keyManager:
               storeFile: "classpath:security/keystore.jks"
               storePass: 'nalle123'
               passwords: ping:'ping123'
               defaultKey: 'ping'
```
