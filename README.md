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
| Property | Syntax | Example Value | Description |

|-------- |------ |------------- |----------- |

| active | boolean | true | States whether or not SAML is active |


### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
