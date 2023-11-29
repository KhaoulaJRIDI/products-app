package ma.app.productsapp.authorization;

import ma.app.productsapp.sec.SecurityUser;
import ma.app.productsapp.services.Policy;
import ma.app.productsapp.services.PolicyEnum;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Optional;
import java.util.function.Supplier;

public class CustomAuthorizationManager<T> implements AuthorizationManager<MethodInvocation> {
AuthenticationTrustResolver trustResolver;
      @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation methodInvocation) {
        if (hasAuthentication(authentication.get())) {
            Policy policyAnnotation = AnnotationUtils.findAnnotation(methodInvocation.getMethod(), Policy.class);
System.out.println("POLICY: "+policyAnnotation);

SecurityUser user = (SecurityUser) authentication.get().getPrincipal();

            return new AuthorizationDecision(Optional.ofNullable(policyAnnotation)
                    .map(Policy::value).filter(policy -> policy == PolicyEnum.OPEN
                            || (policy == PolicyEnum.RESTRICTED && user.hasAccessToRestrictedPolicy())).isPresent());
        }
        return new AuthorizationDecision(false);
    }

    private boolean hasAuthentication(Authentication authentication) {
        return authentication != null  && authentication.isAuthenticated();
    }

  /* private boolean isNotAnonymous(Authentication authentication) {
        return !this.trustResolver.isAnonymous(authentication);
    }*/


}



