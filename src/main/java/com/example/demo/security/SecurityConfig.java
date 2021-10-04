package com.example.demo.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private PasswordEncoder passwordEncoder; 
	/*
	 	Authentication
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		auth.jdbcAuthentication()
			.dataSource(dataSource)
			.usersByUsernameQuery("select uname,upwd,uenabled from users_tab where uname=?")
			.authoritiesByUsernameQuery("select uname,urole from users_tab where uname=?")
			.passwordEncoder(passwordEncoder);
	}
	
	/*
	 * Authorization
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.authorizeRequests()
			.antMatchers("/user/admin").hasAuthority("ADMIN")
			.antMatchers("/user/employee").hasAuthority("EMPLOYEE")
			.antMatchers("/user/student").hasAuthority("STUDENT")
			.antMatchers("/user/welcome").authenticated()
			.anyRequest().authenticated()
			.and()
			.formLogin()
			.defaultSuccessUrl("/user/welcome",true)
			.and()
			.logout()
			.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
			.and()
			.exceptionHandling()
			.accessDeniedPage("/user/access-denied")
			;
			
	}
	
	
	
}
