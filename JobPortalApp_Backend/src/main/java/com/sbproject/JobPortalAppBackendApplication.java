package com.sbproject;

import java.util.Optional;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.sbproject.model.AppUser;
import com.sbproject.repo.UserRepository;

@SpringBootApplication
public class JobPortalAppBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(JobPortalAppBackendApplication.class, args);
		
		 
	}
	
	
}
