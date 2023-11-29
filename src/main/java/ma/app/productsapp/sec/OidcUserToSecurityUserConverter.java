package ma.app.productsapp.sec;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class OidcUserToSecurityUserConverter implements Converter<OidcUser, SecurityUser> {

    @Override
    public SecurityUser convert(OidcUser oidcUser) {
        SecurityUser securityUser = new SecurityUser();
        securityUser.setUserName(oidcUser.getName());



        // Convert OidcUser authorities to SimpleGrantedAuthority objects
        securityUser.setGrantedAuthorityList(oidcUser.getAuthorities()
                .stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthority()))
                .collect(Collectors.toList()));

        return securityUser;
    }

    public Collection<SimpleGrantedAuthority> convertAuthorities(OidcUser oidcUser) {
        return oidcUser.getAuthorities()
                .stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthority()))
                .collect(Collectors.toList());
    }
}

