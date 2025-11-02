package com.sbproject.controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.sbproject.model.JobPost;
import com.sbproject.repo.JobRepo;
import com.sbproject.service.JobService;
import com.sbproject.service.JwtService;

@RestController
@RequestMapping("/api/jobs")
public class JobController {

    @Autowired
    private JobService service;

    @Autowired
    private JwtService jwtservice;

    @Autowired
    private JobRepo repo;

    // ------------------- Public Endpoints -------------------
    @GetMapping
    public List<JobPost> getAllJobPosts() {
        return service.getAllJobPosts();
    }

    @GetMapping("/{postId}")
    public JobPost getJob(@PathVariable Long postId) {
        return service.getJob(postId);
    }

    @PutMapping("/admin/{id}")
    public ResponseEntity<?> updateJob(@PathVariable Long id,
                                       @RequestBody JobPost updatedJob,
                                       @RequestHeader("Authorization") String token) {
        String adminEmail = jwtservice.extractUsername(token.replace("Bearer ", ""));
        try {
            service.updateJobByAdmin(id, updatedJob, adminEmail);
            return ResponseEntity.ok(Map.of("message", "Job updated successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).body(Map.of("message", e.getMessage()));
        }
    }

    @DeleteMapping("/admin/{id}")
    public ResponseEntity<?> deleteJob(@PathVariable Long id,
                                       @RequestHeader("Authorization") String token) {
        String adminEmail = jwtservice.extractUsername(token.replace("Bearer ", ""));
        try {
            service.deleteJobByAdmin(id, adminEmail);
            return ResponseEntity.ok(Map.of("message", "Job deleted successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).body(Map.of("message", e.getMessage()));
        }
    }

    @GetMapping("/keyword/{keyword}")
    public List<JobPost> searchByKeyword(@PathVariable String keyword) {
        return service.search(keyword);
    }

    // ------------------- Admin Endpoints -------------------
    @PreAuthorize("hasAnyRole('ADMIN','SUPER_ADMIN')")
    @PostMapping("/admin/add")
    public ResponseEntity<?> addJob(@RequestBody JobPost job,
                                    @RequestHeader("Authorization") String token) {
        String adminEmail = jwtservice.extractUsername(token.replace("Bearer ", ""));
        job.setCreatedBy(adminEmail); // set logged-in admin as creator
        service.addJobPost(job);
        return ResponseEntity.ok(Map.of("message", "Job added successfully"));
    }

    

    
    @PreAuthorize("hasAnyRole('ADMIN','SUPER_ADMIN')")
    @GetMapping("/admin")
    public List<JobPost> getJobsByAdmin(@RequestHeader("Authorization") String token) {
        String adminEmail = jwtservice.extractUsername(token.replace("Bearer ", ""));
        System.out.println("Filtering jobs for admin email: [" + adminEmail + "]");
        return service.findByCreatedBy(adminEmail);
    }

    // ------------------- Sample Load Data -------------------
    @PreAuthorize("hasAnyRole('ADMIN','SUPER_ADMIN')")
    @GetMapping("/admin/load")
    public String loadData() {
        service.load();
        return "Data loaded successfully";
    }
}
