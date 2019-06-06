## SAML 2.0 Plugin for Grails 3

This plugin provides SAML 2.0 support for Grails 3 applications.  It was originally built from the Plugin that supported Grails 2 applications.  It enables SAML configuration directly from your application.yml or application.groovy without having to manually configure the Spring SAML Plugin and Grails Spring Security Plugin

### Plugin Compatibility with Grails

* Grails 3.0.x - Use Version 3.0.x of the plugin
* Grails 3.1.x - Use Version 3.1.x of the plugin
* Grails 3.3.x - Use Version 3.3.x of the plugin

### Installation
**Maven**

```xml
<dependency>
    <groupId>org.grails.plugins</groupId>
    <artifactId>spring-security-saml</artifactId>
    <version>3.3.1</version>
    <type>pom</type>
</dependency>
```

**Gradle**

```gradle
compile 'org.grails.plugins:spring-security-saml:3.3.1'
```

NOTE: you may have to add the following repositories

```
repositories {
    maven { url "http://central.maven.org/maven2/"}
    maven { url "https://build.shibboleth.net/nexus/content/repositories/releases"}
    maven { url "https://build.shibboleth.net/nexus/content/groups/public/"}
    maven { url "https://code.lds.org/nexus/content/groups/main-repo"}
    maven { url "http://repository.jboss.org/maven2/"}
}
```

Since 3.3.1 the builds have been uploaded to valentingoebel's bintray repository.
The following lines are mandatory:

```
repositories {
    maven { url "https://dl.bintray.com/valentingoebel/plugins" }
}
```

See the [documentation page](https://jeffwils.github.io/grails-spring-security-saml/) for more information.
