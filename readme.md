# PoC for Spring Boot 2 + Spring Security 5 + Keycloak 3.4.3
 
This example project uses the OpenID Connect support in Spring Security 5 without using the Keycloak adapter  
and is inspired by [this](http://info.michael-simons.eu/2017/12/28/use-keycloak-with-your-spring-boot-2-application/) blog post by Michael Simons.
 
 Features:
 - SSO / SLO
 - Support for extracting roles from Keycloak AccessToken
 - Link to Keycloak Account page with back-link to the application

## Setup

Import the `demo` realm into Keycloak via

```
bin/standalone.sh -Dkeycloak.migration.action=import
-Dkeycloak.migration.provider=singleFile -Dkeycloak.migration.file=/path/to/demo-realm.json
-Dkeycloak.migration.strategy=OVERWRITE_EXISTING
```

Keycloak is assumed to run on port 8080 on localhost.  
The demo realm contains two users `tester` and `admin` both with password `test`.
 
The example runs on port 8082.

