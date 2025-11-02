package com.sbproject.controller;

import com.sbproject.model.AppUser;
import com.sbproject.repo.UserRepository;
import com.sbproject.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:5173") // adjust frontend port if needed
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    // ✅ Register endpoint
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AppUser user) {
        try {
            AppUser saved = userService.register(user);
            return ResponseEntity.ok(Map.of(
                    "message", "Registered successfully",
                    "email", saved.getEmail(),
                    "role", saved.getRole()
            ));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    // ✅ Login endpoint
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String password = body.get("password");
        Map<String, Object> response = userService.login(email, password);

        if ("error".equals(response.get("status"))) {
            return ResponseEntity.status(401).body(response);
        }
        return ResponseEntity.ok(response);
    }

    // ✅ Get all users (for SuperAdmin dashboard)
    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers() {
       
        return ResponseEntity.ok(userService.getAllUsers());
    }

    // ✅ Get only Admins (for SuperAdmin dashboard table)
    @GetMapping("/admins")
    public ResponseEntity<?> getAllAdmins() {
       
        return ResponseEntity.ok(userService.getAllAdmins());
    }

    // ✅ Delete user by ID (SuperAdmin can remove admins)
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        Optional<AppUser> user = userRepository.findById(id);
        if (user.isEmpty()) {
            return ResponseEntity.status(404).body(Map.of("message", "User not found"));
        }
        userRepository.deleteById(id);
        return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
    }
}
