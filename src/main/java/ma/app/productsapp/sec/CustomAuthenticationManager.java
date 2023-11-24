package ma.app.productsapp.sec;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public class CustomAuthenticationManager implements AuthenticationProvider, AuthenticationManager {

    private final UserDetailsService userDetailsService;

    public CustomAuthenticationManager(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Perform your custom authentication logic here
        if (passwordMatches(password, userDetails.getPassword())) {
            // Authentication succeeded
            return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        } else {
            // Authentication failed
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    private boolean passwordMatches(String rawPassword, String encodedPassword) {
        // Implement your password matching logic, e.g., using a password encoder
        // For demonstration purposes, we'll compare raw and encoded passwords directly
        return rawPassword.equals(encodedPassword);
    }
}
