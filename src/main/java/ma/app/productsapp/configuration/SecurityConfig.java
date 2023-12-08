/*
package ma.app.productsapp.configuration;

import ma.app.productsapp.mappers.GrantedAuthoritiesExtractor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
public class SecurityConfig {


    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity httpSecurity, CustomUserDetailService customUserDetailService, BCryptPasswordEncoder bCryptPasswordEncoder) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(customUserDetailService)
                .passwordEncoder(bCryptPasswordEncoder);
        return authenticationManagerBuilder.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailService("admin", "admin", Set.of("client-admin"));
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


    @Bean
    public AuthenticationManager AuthenticationManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(customAuthenticationProvider());
        return auth.build();
    }

    @Bean
    public AuthenticationProvider customAuthenticationProvider() {
        return (AuthenticationProvider) new CustomAuthenticationProvider();
    }

    @Order(1)
    @Bean
    public SecurityFilterChain clientFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests()
                .requestMatchers(new AntPathRequestMatcher("/"))
                .permitAll()
                .anyRequest()
                .authenticated();

        http

                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS).disable()
                .oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> {
                    httpSecurityOAuth2ResourceServerConfigurer
                            .jwt()
                            .jwtAuthenticationConverter(grantedAuthoritiesExtractorConverter());
                });



        return http.build();
    }


    @Bean
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests()
                .requestMatchers(new AntPathRequestMatcher("/products/**"))
                .hasAuthority("client-admin")
                .anyRequest()
                .authenticated();

        return http.build();
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

   /* @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

*/





