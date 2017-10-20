package com.fantasy.tools.fantasy_tools.com.fantasy.tools.oath;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.filter.OAuth2AuthenticationFailureEvent;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetailsSource;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class YahooOAuth2ClientAuthenticationProcessingFilter extends OAuth2ClientAuthenticationProcessingFilter {

    private static final String REFRESH_TOKEN_VALUE = "refresh_token_value";
    private static final String XOAUTH_YAHOO_GUID = "xoauth_yahoo_guid";
    private static final String YAHOO_GUID_KEY = "xoauth_yahoo_guid";
    private ApplicationEventPublisher eventPublisher;
    private ResourceServerTokenServices tokenServices;
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new OAuth2AuthenticationDetailsSource();


    public YahooOAuth2ClientAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    public void setTokenServices(ResourceServerTokenServices tokenServices) {
        this.tokenServices = tokenServices;
        super.setTokenServices(tokenServices);
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
        super.setApplicationEventPublisher(eventPublisher);
    }

    private void publish(ApplicationEvent event) {
        if (this.eventPublisher != null) {
            this.eventPublisher.publishEvent(event);
        }
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        OAuth2AccessToken accessToken;
        BadCredentialsException bad;
        try {
            accessToken = this.restTemplate.getAccessToken();
        } catch (OAuth2Exception exception) {
            bad = new BadCredentialsException("Could not obtain access token", exception);
            this.publish(new OAuth2AuthenticationFailureEvent(bad));
            throw bad;
        }

        try {
            OAuth2Authentication result = this.tokenServices.loadAuthentication(accessToken.getValue());
            if (this.authenticationDetailsSource != null) {
                request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, accessToken.getValue());
                request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, accessToken.getTokenType());

                Map<String, Object> yahooDetailsMap = new HashMap<>();
                yahooDetailsMap.put(REFRESH_TOKEN_VALUE, accessToken.getRefreshToken());
                yahooDetailsMap.put(XOAUTH_YAHOO_GUID, accessToken.getAdditionalInformation().get(YAHOO_GUID_KEY));

                OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails)this.authenticationDetailsSource.buildDetails(request);
                details.setDecodedDetails(yahooDetailsMap);
                result.setDetails(details);
            }

            this.publish(new AuthenticationSuccessEvent(result));
            return result;
        } catch (InvalidTokenException exception) {
            bad = new BadCredentialsException("Could not obtain user details from token", exception);
            this.publish(new OAuth2AuthenticationFailureEvent(bad));
            throw bad;
        }
    }

}
