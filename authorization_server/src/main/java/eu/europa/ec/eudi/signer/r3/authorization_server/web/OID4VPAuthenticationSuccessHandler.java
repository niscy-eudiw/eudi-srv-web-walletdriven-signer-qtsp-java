package eu.europa.ec.eudi.signer.r3.authorization_server.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Enumeration;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

public class OID4VPAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        super.onAuthenticationSuccess(request, response, chain, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println("here");

        Collection<String> headers = response.getHeaderNames();
        for(String h: headers){
            System.out.println(h+ ": "+request.getSession().getAttribute(h));
        }

        Enumeration<String> att = request.getSession().getAttributeNames();
        while(att.hasMoreElements()){
            String a = att.nextElement();
            System.out.println(a+ ": "+request.getSession().getAttribute(a));
        }
        
        Authentication a1 = SecurityContextHolder.getContext().getAuthentication();
        if(a1 == null)
            System.out.println("AuthenticationManagerToken is null");
        System.out.println(a1.getPrincipal());

        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        String session_id = request.getParameter("session_id");
        System.out.println(session_id);
        // String authorize_request = URLDecoder.decode(session_id, StandardCharsets.UTF_8);
        // System.out.println("Authorization URL: "+authorize_request);
        
        this.redirectStrategy.sendRedirect(request, response, session_id);

        
    }
}
