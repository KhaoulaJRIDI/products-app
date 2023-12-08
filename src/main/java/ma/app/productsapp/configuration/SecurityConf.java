package ma.app.productsapp.configuration;


import lombok.RequiredArgsConstructor;
import ma.app.productsapp.mappers.GrantedAuthoritiesExtractor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConf {

    @Bean
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Order(1)
    @Bean
    public SecurityFilterChain clientFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers(new AntPathRequestMatcher("/"))
                .permitAll()
                .anyRequest()
                .authenticated();


        http.oauth2Login();
             // .and()
            //    .logout()
               // .addLogoutHandler(keycloakLogoutHandler)
           //     .logoutSuccessUrl("/");
        return http.build();
    }



    @Order(2)
    @Bean
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers(new AntPathRequestMatcher("/products/**"))
                .hasAuthority("client-admin")
                .requestMatchers(new AntPathRequestMatcher("/suppliers"))
                .hasAuthority("client-admin")
                .anyRequest()

                .authenticated();
        http.oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> {
            httpSecurityOAuth2ResourceServerConfigurer
                    .jwt()
                    .jwtAuthenticationConverter(grantedAuthoritiesExtractorConverter());
        });
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .build();
    }

    @Bean
    Converter<Jwt, AbstractAuthenticationToken> grantedAuthoritiesExtractorConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesExtractor());
        return jwtAuthenticationConverter;
    }

    @Bean
    GrantedAuthoritiesExtractor grantedAuthoritiesExtractor() {
        return new GrantedAuthoritiesExtractor();
    }
}