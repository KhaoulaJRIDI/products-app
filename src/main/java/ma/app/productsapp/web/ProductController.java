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
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import org.springframework.hateoas.PagedModel;

@Controller

public class ProductController{
    @Autowired
    private ProductRepository productRepository;
    //@Autowired
    //private KeycloakRestTemplate keycloakRestTemplate;


    @GetMapping("/index")
    public String indexing(){
        return "index";
    }
    @GetMapping("/")
    @PreAuthorize("hasRole('ROLE_client-user')")
    public String index(){
        return "index";
    }
    @GetMapping("/products")
    @PreAuthorize("hasRole('ROLE_client-admin')")
    public String products(Model model){
        model.addAttribute("products",productRepository.findAll());
       return "products";

    }
/* @GetMapping("/suppliers")
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
    }*/


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
