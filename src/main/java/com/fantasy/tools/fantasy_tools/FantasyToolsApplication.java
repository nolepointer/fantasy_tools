package com.fantasy.tools.fantasy_tools;

import com.fantasy.tools.fantasy_tools.com.fantasy.tools.oath.YahooOAuth2ClientAuthenticationProcessingFilter;
import com.fantasy.tools.fantasy_tools.com.fantasy.tools.oath.YahooUserInfoTokenServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.Filter;
import java.security.Principal;

@SpringBootApplication
@EnableOAuth2Client
@RestController
public class FantasyToolsApplication extends WebSecurityConfigurerAdapter {

	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	public static void main(String[] args) {
		SpringApplication.run(FantasyToolsApplication.class, args);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.antMatcher("/**")
				.authorizeRequests()
				.antMatchers("/", "/login**", "/webjars/**")
				.permitAll()
				.anyRequest()
				.authenticated()
				.and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);;
	}

	private Filter ssoFilter() {
		OAuth2ClientAuthenticationProcessingFilter yahooFilter = new YahooOAuth2ClientAuthenticationProcessingFilter("/login");
		OAuth2RestTemplate yahooTemplate = new OAuth2RestTemplate(yahoo(), oauth2ClientContext);
		yahooFilter.setRestTemplate(yahooTemplate);
		UserInfoTokenServices tokenServices = new YahooUserInfoTokenServices(yahooResource().getUserInfoUri(), yahoo().getClientId());
		tokenServices.setRestTemplate(yahooTemplate);
		yahooFilter.setTokenServices(tokenServices);
		return yahooFilter;
	}

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	@Bean
	@ConfigurationProperties("yahoo.client")
	public AuthorizationCodeResourceDetails yahoo() {
		return new AuthorizationCodeResourceDetails();
	}

	@Bean
	@ConfigurationProperties("yahoo.resource")
	public ResourceServerProperties yahooResource() {
		return new ResourceServerProperties();
	}

	@RequestMapping("/user")
	public Principal user(Principal principal) {
		return principal;
	}

}
