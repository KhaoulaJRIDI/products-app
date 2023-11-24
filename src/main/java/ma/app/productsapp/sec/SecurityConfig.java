package ma.app.productsapp.sec;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity

public class SecurityConfig {
    private final JwtAuthConverter jwtAuthConverter;
    private AuthenticationManagerBuilder authManager;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {




        http
                .authorizeHttpRequests((requests) -> requests.requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll());
        http.headers().frameOptions().disable();
        http.authorizeHttpRequests((requests) -> requests.requestMatchers(new AntPathRequestMatcher("/index")).permitAll());
        http.authorizeHttpRequests((requests) -> requests.requestMatchers(new AntPathRequestMatcher("/products")).authenticated());

        http   .httpBasic(Customizer.withDefaults())
                .logout(logout -> logout.logoutSuccessUrl("/").permitAll())
                .oauth2Login(oauth2 ->
                        oauth2.userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService())));


            http
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthConverter);

        http
                .sessionManagement()
                .sessionCreationPolicy(STATELESS);


        http
                .cors() // by default uses a Bean by the name of corsConfigurationSource
                .and().csrf().disable()
                .formLogin().disable()
                 .httpBasic().disable();

            return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public OidcUserService oidcUserService() {
        return new CustomOidcUserService();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService();
    }

    @Bean
    public AuthenticationFailureHandler customAuthenticationFailureHandler() {
        return (request, response, exception) -> {
            // Customize the behavior on login failure (e.g., redirect to a custom error page)
            response.sendRedirect("/login?error");
        };
    }
}
