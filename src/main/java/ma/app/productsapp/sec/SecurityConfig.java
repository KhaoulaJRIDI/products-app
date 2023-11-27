package ma.app.productsapp.sec;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfig {
    private final KeycloakLogoutHandler keycloakLogoutHandler;
    private final JwtAuthConverter jwtAuthConverter;
    SecurityConfig(KeycloakLogoutHandler keycloakLogoutHandler, JwtAuthConverter jwtAuthConverter) {
        this.keycloakLogoutHandler = keycloakLogoutHandler;
        this.jwtAuthConverter = jwtAuthConverter;
    }

    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
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
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .build();
    }
}