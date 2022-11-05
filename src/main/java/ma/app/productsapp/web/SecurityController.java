package ma.app.productsapp.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

@Controller
public class SecurityController {
@GetMapping("/logout")
    public String logout(HttpServletRequest request) throws ServletException {
request.logout();
return "redirect:/";
}


}
