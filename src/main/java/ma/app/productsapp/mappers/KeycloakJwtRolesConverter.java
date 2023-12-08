package ma.app.productsapp.mappers;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

public class KeycloakJwtRolesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    /**
     * Prefix used for realm level roles.
     */
    public static final String PREFIX_REALM_ROLE = "ROLE_realm_";
    /**
     * Prefix used in combination with the resource (client) name for resource level roles.
     */
    public static final String PREFIX_RESOURCE_ROLE = "ROLE_";

    /**
     * Name of the claim containing the realm level roles
     */
    private static final String CLAIM_REALM_ACCESS = "realm_access";
    /**
     * Name of the claim containing the resources (clients) the user has access to.
     */
    private static final String CLAIM_RESOURCE_ACCESS = "resource_access";
    /**
     * Name of the claim containing roles. (Applicable to realm and resource level.)
     */
    private static final String CLAIM_ROLES = "roles";


    /**
     * Extracts the realm and resource level roles from a JWT token distinguishing between them using prefixes.
     */
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        // Collection that will hold the extracted roles
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        // Realm roles
        // Get the part of the access token that holds the roles assigned on realm level
        Map<String, Collection<String>> realmAccess = jwt.getClaim(CLAIM_REALM_ACCESS);

        // Verify that the claim exists and is not empty
        if (realmAccess != null && !realmAccess.isEmpty()) {
            // From the realm_access claim get the roles
            Collection<String> roles = realmAccess.get(CLAIM_ROLES);
            // Check if any roles are present
            if (roles != null && !roles.isEmpty()) {
                // Iterate of the roles and add them to the granted authorities
                Collection<GrantedAuthority> realmRoles = roles.stream()
                        // Prefix all realm roles with "ROLE_realm_"
                        .map(role -> new SimpleGrantedAuthority(PREFIX_REALM_ROLE + role))
                        .collect(Collectors.toList());
                grantedAuthorities.addAll(realmRoles);
            }
        }

        // Resource (client) roles
        // A user might have access to multiple resources all containing their own roles. Therefore, it is a map of
        // resource each possibly containing a "roles" property.
        Map<String, Map<String, Collection<String>>> resourceAccess = jwt.getClaim(CLAIM_RESOURCE_ACCESS);

        // Check if resources are assigned
        if (resourceAccess != null && !resourceAccess.isEmpty()) {
            // Iterate of all the resources
            resourceAccess.forEach((resource, resourceClaims) -> {
                // Iterate of the "roles" claim inside the resource claims
                resourceClaims.get(CLAIM_ROLES).forEach(
                        // Add the role to the granted authority prefixed with ROLE_ and the name of the resource
                        role -> grantedAuthorities.add(new SimpleGrantedAuthority(PREFIX_RESOURCE_ROLE + resource + "_" + role))
                );
            });
            System.out.println("GRANTED AUTHORITY: "+grantedAuthorities);
        }

        return grantedAuthorities;
    }
}