package ma.app.productsapp.authentication;
import ma.app.productsapp.sec.SecurityUser;

import org.springframework.context.annotation.Role;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.*;
import java.util.stream.Collectors;

public class CustomUserDetailService implements UserDetailsService {
    private final Map<String, SecurityUser> userMap = new HashMap<>();
    private OidcUser oidcUser;
    private SecurityUser user;


    public  CustomUserDetailService(BCryptPasswordEncoder bCryptPasswordEncoder) {
        userMap.put("user", createUser("user", bCryptPasswordEncoder.encode("userPass"), false, "USER"));
        userMap.put("admin", createUser("admin", bCryptPasswordEncoder.encode("adminPass"), true, "client_admin", "client_user"));


    }

    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        
        return Optional.ofNullable(userMap.get(username))
                .orElseThrow(() -> new UsernameNotFoundException("User " + username + " does not exists"));

    }

    private SecurityUser createUser(String userName, String password, boolean withRestrictedPolicy, String... role) {


            return SecurityUser.builder().userName(userName)
                    .password(password)
                    .grantedAuthorityList(Arrays.stream(role)
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList()))
                    .accessToRestrictedPolicy(withRestrictedPolicy)
                    .build();


    }
    /*private Collection<? extends GrantedAuthority> getAuthorities(Collection<Role> roles) {
        List<GrantedAuthority> authorities
                = new ArrayList<>();
        for (Role role: roles) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
            role.getPrivileges().stream()
                    .map(p -> new SimpleGrantedAuthority(p.getName()))
                    .forEach(authorities::add);
        }

        return authorities;
    }*/

}


