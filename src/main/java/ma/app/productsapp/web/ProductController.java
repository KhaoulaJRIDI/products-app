package ma.app.productsapp.web;

import lombok.Data;
import ma.app.productsapp.repositories.ProductRepository;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import org.springframework.hateoas.PagedModel;
import org.springframework.web.client.RestTemplate;

@Controller

public class ProductController{
    @Autowired
    private ProductRepository productRepository;
    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/index")
    public String indexing(){
        return "index";
    }
    @GetMapping("/")
    @PreAuthorize("hasRole('client-user')")
    public String index(){
        return "index";
    }
    @GetMapping("/products")
    @PreAuthorize("hasRole('Role_client-admin')") // or any other authority from the logs
    public String products(Model model){
        System.out.println("User Authorities: " + SecurityContextHolder.getContext().getAuthentication().getAuthorities());
        System.out.println("User Principal: " + SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        model.addAttribute("products",productRepository.findAll());
       return "products";

    }
/*
@GetMapping("/suppliers")

    public String suppliers(Model model){

    PagedModel<Supplier> pageSuppliers=
                keycloakRestTemplate.getForObject("http://localhost:8083/suppliers",PagedModel.class);
        model.addAttribute("suppliers",pageSuppliers);
        return "suppliers";
    }
    @ExceptionHandler(Exception.class)
    public String exceptionHandler(Exception e, Model model){
        model.addAttribute("errorMessage","problème d'autorisation");
        return "errors";
    }
*/


    @GetMapping("/suppliers")
    public String suppliers(Model model, Authentication authentication,@AuthenticationPrincipal UserDetails userDetails) {

        if (userDetails != null) {
            String clientRegistrationId = "products-app"; // Replace with your actual client registration ID
            OAuth2AuthorizedClient authorizedClient =
                    authorizedClientService.loadAuthorizedClient(clientRegistrationId, userDetails.getUsername());


            if (authorizedClient != null) {
                String accessToken = authorizedClient.getAccessToken().getTokenValue();

                if (authentication != null && authentication.getPrincipal() instanceof OidcUser) {

                    OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
                    String username = oidcUser.getName();
                    model.addAttribute("username", username);


                    authorizedClient = authorizedClientService.loadAuthorizedClient(
                            "products-app", oidcUser.getName());

                    // Set the access token in the request header
                    OAuth2AuthorizedClient finalAuthorizedClient = authorizedClient;
                    restTemplate.getInterceptors().add((request, body, execution) -> {
                        request.getHeaders().setBearerAuth(finalAuthorizedClient.getAccessToken().getTokenValue());
                        return execution.execute(request, body);
                    });


                    PagedModel pageSuppliers = restTemplate.getForObject("http://localhost:8083/suppliers",PagedModel.class);
                    //.getForObject("http://localhost:8083/suppliers", PagedModel.class);


                    // Clear the access token from the request header
                    restTemplate.getInterceptors().removeIf(interceptor -> interceptor.getClass().getName().contains("BearerTokenInterceptor"));
                    model.addAttribute("suppliers", pageSuppliers);
                }


            }

        }
        return "suppliers";
    }
    @ExceptionHandler(Exception.class)
    public String exceptionHandler(Exception e, Model model){
        model.addAttribute("errorMessage","problème d'autorisation");
        return "errors";
    }


    @GetMapping("/jwt")
    @ResponseBody
    public Map<String,String> map(HttpServletRequest request){
        KeycloakAuthenticationToken token =(KeycloakAuthenticationToken) request.getUserPrincipal();
        KeycloakPrincipal principal=(KeycloakPrincipal)token.getPrincipal();
        KeycloakSecurityContext keycloakSecurityContext=principal.getKeycloakSecurityContext();
        Map<String,String> map = new HashMap<>();
        map.put("access_token", keycloakSecurityContext.getTokenString());
        return map;
    }
}
@Data
class Supplier{
    private Long id;
    private String name;
    private String email;
}
