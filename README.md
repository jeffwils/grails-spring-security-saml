## SAML 2.0 Plugin for Grails 3

This plugin provides SAML 2.0 support for Grails 3 applications.  It was originally built from the Plugin that supported Grails 2 applications.  It enables SAML configuration directly from your application.yml or application.groovy without having to manually configure the Spring SAML Plugin and Grails Spring Security Plugin

### Installation
**Maven**
```xml
<dependency>
  <groupId>org.grails.plugins</groupId>
  <artifactId>spring-security-saml</artifactId>
  <version>3.0.0</version>
  <type>pom</type>
</dependency>
```
**Gradle**
```gradle
compile 'org.grails.plugins:spring-security-saml:3.0.0'
```

### Configuration
The Plugin basically creates a bridge from your application configuration to both the Spring Security SAML Plugin and the Grails Spring Security Plugin.  Instead of having to map all of the beans in your application, The plugin wires the SAML Plugin beans from your application configuration.

All configuration items are preceeded with grails >> plugin >> springsecurity >> saml.  The following is a list of all of the configuration options available.

#### Authentication Provider
The plugin sets up a SAML Authentication provider **samlAuthenticationProvider** which can be referenced in the Grails Spring Security Plugin configuration
```yaml
grails:
   plugins:
      springsecurity:
         providerNames: ['samlAuthenticationProvider', ......]
```
#### Property Table
All of these properties can be put in either application.yml or application.groovy and they are all prefixed with:
**grails.plugins.springsecurity.saml**


| Property | Syntax | Example Value | Description | 
|--------|------|-------------|-----------| 
| active | boolean | true | States whether or not SAML is active |
| afterLoginUrl | url string | '/' | Redirection Url in your application upon successful login from the IDP |
| afterLogoutUrl | url string | '/' | Redirection Url in your application upon successful logout from the IDP |
| responseSkew = 300 |
| signatureAlgorithm | String Value | 'rsa-sha256' | Accepted Values are From org.opensaml.xml.signature.SignatureConstants |
| digestAlgorithm | String Value | 'sha256' | Accepted Values are From org.opensaml.xml.encryption.EncryptionConstants |
| userAttributeMappings | Map | [username:'funkyUserNameFromIDP'] | Allows Custom Mapping if both Application and IDP Attribute Names cannot be changed. |
| userGroupAttribute | String Value | 'memberOf' | Corresponds to the Role Designator in the SAML Assertion from the IDP |
| userGroupToRoleMapping | Map [Spring Security Role: Saml Assertion Role] | [ROLE_MY_APP_ROLE: 'CN=MYSAMLGROUP,OU=MyAppGroups,DC=myldap,DC=example,DC=com'] | This maps the Spring Security Roles in your application to the roles from the SAML Assertion.  Only roles in this Map will be resolved. |
| autoCreate.active | boolean | false | If you want the plugin to generate users in the DB as they are authenticated via SAML
| autoCreate.key | domain class unique identifier | 'id' | if autoCreate active is true then this is the unique id field of the db table |
| autoCreate.assignAuthorities | boolean | false | If you want the plugin to insert the authorities that come from the SAML message into the UserRole Table. |
| metadata.providers | Map [idp alias: idp file reference] | [ping:"/pathtoIdpFile/myIdp.xml"] | Map of idp providers. Contain an alias and reference to the idp xml file |
| metadata.defaultIdp | String | 'ping' | the default Idp from the ones listed in the metadata.provider map |
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

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
