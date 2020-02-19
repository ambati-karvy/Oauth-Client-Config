package com.remote.web;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping( "/v1" )
public class PublicController {
	
	@RequestMapping( value = "/get-xsrf", method = RequestMethod.GET )
	public String getToken() {
		
		return "Sucessfully generated";
	}

}
