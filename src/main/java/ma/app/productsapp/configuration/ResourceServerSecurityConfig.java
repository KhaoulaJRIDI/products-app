/*
package ma.app.productsapp.configuration;

import ma.app.productsapp.mappers.GrantedAuthoritiesExtractor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

*/
/*
@EnableWebSecurity
@Configuration
public class ResourceServerSecurityConfig {
@Autowired
GrantedAuthoritiesExtractor grantedAuthoritiesExtractor;

    public void configure (HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()

                .authorizeHttpRequests()
                .requestMatchers(new AntPathRequestMatcher("/products/**"))
                .hasAuthority("Role_client-admin")
                .and()

                .oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> {
                    httpSecurityOAuth2ResourceServerConfigurer
                            .jwt()
                            .jwtAuthenticationConverter(grantedAuthoritiesExtractorConverter());
                });

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
*/