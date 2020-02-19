package com.remote.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfiguration {
	
	@Autowired SecurityFilter securityFilter;
	
    @Bean
    public FilterRegistrationBean dawsonApiFilter() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(securityFilter);
        registration.setOrder(1);
        registration.addUrlPatterns("/rest/*");
        return registration;
    }
}
