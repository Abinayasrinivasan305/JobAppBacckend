package com.sbproject.controller;


import com.sbproject.model.AppUser;
import com.sbproject.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('SUPER_ADMIN')")
public class AdminController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/users")
    public List<AppUser> listAllUsers() {
        return userRepository.findAll();
    }

    @DeleteMapping("/users/{id}")
    public Map<String, String> deleteUser(@PathVariable Long id) {
        userRepository.deleteById(id);
        return Map.of("message", "User deleted");
    }
}
