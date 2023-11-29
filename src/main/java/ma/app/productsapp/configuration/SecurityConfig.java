package ma.app.productsapp.configuration;

import ma.app.productsapp.authorization.CustomAuthorizationManager;
import ma.app.productsapp.authentication.CustomUserDetailService;
import ma.app.productsapp.sec.JwtAuthConverter;
import ma.app.productsapp.sec.KeycloakLogoutHandler;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.support.JdkRegexpMethodPointcut;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.springframework.beans.factory.config.BeanDefinition.ROLE_INFRASTRUCTURE;



@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class SecurityConfig {
    private final JwtAuthConverter jwtAuthConverter;
    private final KeycloakLogoutHandler keycloakLogoutHandler;

    public SecurityConfig(JwtAuthConverter jwtAuthConverter, KeycloakLogoutHandler keycloakLogoutHandler) {
        this.jwtAuthConverter = jwtAuthConverter;
        this.keycloakLogoutHandler = keycloakLogoutHandler;
    }


    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity httpSecurity, UserDetailsService userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailsService)
                .passwordEncoder(bCryptPasswordEncoder);
        return authenticationManagerBuilder.build();
    }

    @Bean
    public UserDetailsService userDetailsService(BCryptPasswordEncoder bCryptPasswordEncoder) {
        return new CustomUserDetailService(bCryptPasswordEncoder);
    }

   @Bean
    public AuthorizationManager<MethodInvocation> authorizationManager() {
        return new CustomAuthorizationManager<>();
    }

  @Bean
    @Role(ROLE_INFRASTRUCTURE)
    public Advisor authorizationManagerBeforeMethodInterception(AuthorizationManager<MethodInvocation> authorizationManager) {
        JdkRegexpMethodPointcut pattern = new JdkRegexpMethodPointcut();
        pattern.setPattern("ma.app.productsapp.services.*");
        return new AuthorizationManagerBeforeMethodInterceptor(pattern, authorizationManager);
    }
   @Order(1)
    @Bean
    public SecurityFilterChain clientFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .requestMatchers(new AntPathRequestMatcher("/"))
                .permitAll()
                .anyRequest()
                .authenticated();
       http.oauth2Login()

               .and()
               .logout()
               .addLogoutHandler(keycloakLogoutHandler)
               .logoutSuccessUrl("/");
       return http.build();
    }


    @Order(2)
    @Bean
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .requestMatchers(new AntPathRequestMatcher("/products/**"))
                .hasAuthority("client-admin")
                .anyRequest()
                .authenticated();

        http.

               oauth2ResourceServer()
               .jwt()
                .jwtAuthenticationConverter(jwtAuthConverter);


        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        return http.build();
    }

        @Bean
        public BCryptPasswordEncoder bCryptPasswordEncoder() {
            return new BCryptPasswordEncoder();
        }


}

