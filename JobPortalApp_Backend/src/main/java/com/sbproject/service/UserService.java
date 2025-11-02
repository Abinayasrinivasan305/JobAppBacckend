package com.sbproject.service;



import com.sbproject.model.AppUser;

import com.sbproject.repo.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    // 🔹 Register user/admin/superadmin
    public AppUser register(AppUser user) {
        // ✅ Check if email already exists
        Optional<AppUser> existing = userRepo.findByEmail(user.getEmail());
        if (existing.isPresent()) {
            throw new RuntimeException("Email already exists!");
        }

        // ✅ Assign role
        if (user.getRole() == null || user.getRole().isBlank()) {
            user.setRole("ROLE_USER");
        } else {
            switch (user.getRole().toUpperCase()) {
                case "ADMIN":
                    user.setRole("ROLE_ADMIN");
                    break;
                case "SUPER_ADMIN":
                    user.setRole("ROLE_SUPER_ADMIN");
                    break;
                default:
                    user.setRole("ROLE_USER");
            }
        }

        // ✅ Encode password
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // ✅ Save user
        return userRepo.save(user);
    }


    // 🔹 Login user
    public Map<String, Object> login(String email, String password) {
        Optional<AppUser> userOptional = userRepo.findByEmail(email);
        Map<String, Object> response = new HashMap<>();

        if (userOptional.isEmpty() || !passwordEncoder.matches(password, userOptional.get().getPassword())) {
            response.put("status", "error");
            response.put("message", "Invalid email or password!");
            return response;
        }

        AppUser user = userOptional.get();
        String token = jwtService.generateToken(user.getEmail(), user.getRole());

        response.put("status", "success");
        response.put("token", token);
        response.put("email", user.getEmail());
        response.put("role", user.getRole());
        response.put("username", user.getUsername());

        return response;
    }
    
    public List<AppUser> getAllUsers() {
        return userRepo.findAll()
                .stream()
                .filter(u -> "ROLE_USER".equals(u.getRole()))
                .collect(Collectors.toList());
    }

    public List<AppUser> getAllAdmins() {
        return userRepo.findAll()
                .stream()
                .filter(u -> "ROLE_ADMIN".equals(u.getRole()))
                .collect(Collectors.toList());
    }
}