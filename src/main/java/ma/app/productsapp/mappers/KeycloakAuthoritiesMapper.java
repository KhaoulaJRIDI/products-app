package ma.app.productsapp.mappers;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.util.*;
import java.util.stream.Collectors;

public class KeycloakAuthoritiesMapper implements  GrantedAuthoritiesMapper {
           private final String resourceId = "products-app";

  @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {



      Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

        for (GrantedAuthority authority : authorities) {
            // Extract and map roles from JWT to Spring Security authorities
            if (authority instanceof KeycloakAuthenticationToken token) {
                System.out.println("THE AUTHORITY IS:: +++" + authority);
                Collection<? extends GrantedAuthority> resourceRoles =
                        extractResourceRoles(token.getAccount().getKeycloakSecurityContext().getToken());
                mappedAuthorities.addAll(resourceRoles);
                System.out.println("THE AUTHORITY FROM TOKEN IS : "+authority);
            }
            else
            {
                mappedAuthorities.add(authority);
            }

        }

        return mappedAuthorities;
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(AccessToken accessToken) {
        Map<String, AccessToken.Access> resourceAccess;
        Collection<String> resourceRoles;

        if (accessToken == null || accessToken.getResourceAccess() == null) {
            return Set.of();
        }

        resourceAccess = accessToken.getResourceAccess();


        if (resourceAccess.get(resourceId) == null) {
            return Set.of();
        }

        resourceRoles = resourceAccess.get(resourceId).getRoles();

          return resourceRoles
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }



}