package com.remote.config;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import com.remote.model.User;

@EnableResourceServer
@Configuration
public class OAuth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

    private static final String RESOURCE_ID = "resource_id";

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId(RESOURCE_ID).stateless(false);
    }
   /* @Override
    public void configure(HttpSecurity http) throws Exception {
        http.
        csrf()
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .and().
        requestMatchers()
                .requestMatchers(
                        new NegatedRequestMatcher(
                                new OrRequestMatcher(
                                        new AntPathRequestMatcher("/login"),
                                        new AntPathRequestMatcher("/v1/get-xsrf/**"),
                                        new AntPathRequestMatcher("/health/**"),
                                        new AntPathRequestMatcher("/logout"),
                                        new AntPathRequestMatcher("/images/**"),
                                        new AntPathRequestMatcher("/"),
                                        new AntPathRequestMatcher("/*.js"),
                                        new AntPathRequestMatcher("/*.ico"),
                                        new AntPathRequestMatcher("/*.css"),
                                        new AntPathRequestMatcher("/*.png"),
                                        new AntPathRequestMatcher("/*.html"),
                                        new AntPathRequestMatcher("/oauth/authorize"),
                                        new AntPathRequestMatcher("/oauth/confirm_access")
                                )
                        )
                )
                .and()
                .authorizeRequests().anyRequest().authenticated();
    }*/
    
    @Override
    public void configure(final HttpSecurity http) throws Exception {
		        http
		        .sessionManagement()
		        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
		        .and()
		        .csrf()
		        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
		        .and()
		        .authorizeRequests()
		        .antMatchers("/login").permitAll()
		        .antMatchers("/forgot-password").permitAll()
		        .antMatchers("/set-password").permitAll()
		        .antMatchers("/downloadFile").permitAll()
		        .antMatchers("/set-password1").permitAll()
		        .antMatchers("/change-password").permitAll()
		        .antMatchers("/resources/**").permitAll()
                .antMatchers("/rest/roles/**").hasAuthority("RIGHT_EDIT_USERS")
                .anyRequest().authenticated()
                .and().formLogin()
                .loginProcessingUrl("/login")
                .loginPage("/login")
                .successHandler(successHandler())
                .failureHandler(failureHandler())
                .permitAll()
                .and().csrf().disable()
                .logout().permitAll();
    }
    
    @Autowired
    private OAuth2RestTemplate restTemplate;
    
    private AuthenticationSuccessHandler successHandler() {
        return new AuthenticationSuccessHandler() {
          @Override
          public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        
        	HttpSession session = httpServletRequest.getSession();
      	
      		User authUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();  
            session.setAttribute("uname", authUser.getUsername());  
            session.setAttribute("authorities", authentication.getAuthorities());
            
            final Map<String, Object> additionalInfo = new HashMap<>();
            
            additionalInfo.put("user_id", authUser.getId());
			
			Cookie cookie = new Cookie("Token", ""+restTemplate.getAccessToken());
           
			System.out.println("authanticated");
            
            httpServletResponse.addHeader("Authorization", "Bearer "+restTemplate.getAccessToken());
            //httpServletResponse.addCookie(cookie);
            httpServletResponse.setContentType("application/json");
        	httpServletResponse.getWriter().append("{message:Your are login successfully., status: 200}");
            httpServletResponse.setStatus(200);
          }
        };
    }
    
    private AuthenticationFailureHandler failureHandler() {
        return new AuthenticationFailureHandler() {
          @Override
          public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
            httpServletResponse.getWriter().append("Authentication failure");
            httpServletResponse.setStatus(401);
          }
        };
    }

}
