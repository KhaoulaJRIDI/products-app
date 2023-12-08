package ma.app.productsapp.mappers;

import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class CustomAuthoritiesMapper {


    public Collection<? extends GrantedAuthority> mapAuthorities(KeycloakAuthenticationToken token) {
        if (token == null) {
            return List.of(); // or return an empty list if not KeycloakAuthenticationToken
        }

        // Extract roles from the Keycloak token attributes
        Map<String, Object> userAttributes = token.getAccount().getKeycloakSecurityContext().getIdToken().getOtherClaims();
        List<String> keycloakRoles = extractRolesFromUserAttributes(userAttributes);

        // Map Keycloak roles to custom Spring Security roles or authorities
        List<String> customAuthorities = keycloakRoles.stream()
                .map(this::mapToCustomAuthority)
                .collect(Collectors.toList());
        System.out.println("***customAuthorities without adding other claims***");
        customAuthorities.forEach(System.out::println);
        // Add any additional custom authorities based on your requirements

        return customAuthorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

    }

    private List<String> extractRolesFromUserAttributes(Map<String, Object> userAttributes) {
        // Extract roles from the "UserAttributes"
        // The structure might vary based on your Keycloak setup
        List<String> roles = (List<String>) userAttributes.get("roles");
        return roles;
    }

    private String mapToCustomAuthority(String keycloakRole) {
        // Implement your custom mapping logic here
        // For example, you can add a prefix or transform the role name
        return "CUSTOM_" + keycloakRole.toUpperCase();
    }





    /*public Collection<? extends GrantedAuthority> mapAuthorities(KeycloakAuthenticationToken token) {
        if (token == null) {
            return List.of(); // or return an empty list if not KeycloakAuthenticationToken
        }

        // Extract roles from the Keycloak token
        Map<String, AccessToken.Access> resourceAccess = token.getAccount().getKeycloakSecurityContext().getToken().getResourceAccess();
        List<String> keycloakRoles = extractRolesFromResourceAccess(resourceAccess);

        // Map Keycloak roles to custom Spring Security roles or authorities
        List<String> customAuthorities = keycloakRoles.stream()
                .map(this::mapToCustomAuthority)
                .collect(Collectors.toList());

        // Add any additional custom authorities based on your requirements

        return customAuthorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    private List<String> extractRolesFromResourceAccess(Map<String, AccessToken.Access> resourceAccess) {
        // Extract roles from the "resource_access" attribute in the Keycloak token
        // The structure might vary based on your Keycloak setup
        Map<String, Object> productAppRoles = (Map<String, Object>) resourceAccess.get("products-app");
        List<String> roles = (List<String>) productAppRoles.get("roles");
        return roles;
    }

    private String mapToCustomAuthority(String keycloakRole) {
        // Implement your custom mapping logic here
        // For example, you can add a prefix or transform the role name
        return "CUSTOM_" + keycloakRole.toUpperCase();
    }*/
}
