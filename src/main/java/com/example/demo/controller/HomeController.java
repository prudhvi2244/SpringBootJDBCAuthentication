package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping(value = "/user")
public class HomeController {

	@GetMapping(value = "/welcome")
	public String welcomePage()
	{
		return "welcome";
	}
	
	@GetMapping(value = "/admin")
	public String adminePage()
	{
		return "admin";
	}
	
	@GetMapping(value = "/student")
	public String studentPage()
	{
		return "student";
	}
	
	
	@GetMapping(value = "/employee")
	public String employeePage()
	{
		return "employee";
	}
	
	@GetMapping(value = "/access-denied")
	public String accessDeniedPage()
	{
		return "access-denied";
	}
	
	
}
