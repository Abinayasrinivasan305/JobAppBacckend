package com.sbproject.service;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.sbproject.model.AppUser;
import com.sbproject.model.*;
import com.sbproject.repo.UserRepository;

@Service
public class MyUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepository repo;
	
	
	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
	    AppUser user = repo.findByEmail(email)
	                       .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
	    return new UserPrincipal(user);
	}


}