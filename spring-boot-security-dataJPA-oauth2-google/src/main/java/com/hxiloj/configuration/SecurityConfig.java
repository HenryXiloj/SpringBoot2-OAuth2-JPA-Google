package com.hxiloj.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

/**
 * @author Henry
 *
 */

@EnableOAuth2Sso
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter{
    
	@Autowired
	private OAuth2ClientContext oauth2ClientContext;
    
	@Autowired
	private AuthorizationCodeResourceDetails authorizationCodeResourceDetails;
   
	@Autowired
	private ResourceServerProperties resourceServerProperties;
    
	 @Override
	 protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        super.configure(auth);
	 }
	 
	 @Override
     public void configure(WebSecurity web) throws Exception {
        super.configure(web);
     }
	 
	@Override
    protected void configure(HttpSecurity http) throws Exception {

        http
            // Starts authorizing configurations.
            .authorizeRequests()
            // Ignore the "/" and "/index.html"
            .antMatchers("/", "/**.html", "/**.js").permitAll()
            // Authenticate all remaining URLs.
            .anyRequest().fullyAuthenticated()
            .and()
            // Setting the logout URL "/logout" - default logout URL.
            .logout()
            // After successful logout the application will redirect to "/" path.
            .logoutSuccessUrl("/")
            .permitAll()
            .and()
            // Setting the filter for the URL "/google/login".
            .addFilterAt(filter(), BasicAuthenticationFilter.class)
            .csrf()
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }
	
	 /*This method for creating filter for OAuth authentication.*/
    private OAuth2ClientAuthenticationProcessingFilter filter() {
        //Creating the filter for "/google/login" url
        OAuth2ClientAuthenticationProcessingFilter oAuth2Filter = new OAuth2ClientAuthenticationProcessingFilter(
                "/google/login");

        //Creating the rest template for getting connected with OAuth service.
        //The configuration parameters will inject while creating the bean.
        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(authorizationCodeResourceDetails,
                oauth2ClientContext);
        oAuth2Filter.setRestTemplate(oAuth2RestTemplate);

        // Setting the token service. It will help for getting the token and
        // user details from the OAuth Service.
        oAuth2Filter.setTokenServices(new UserInfoTokenServices(resourceServerProperties.getUserInfoUri(),
                resourceServerProperties.getClientId()));

        return oAuth2Filter;
    }
}
