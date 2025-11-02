package com.sbproject.model;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class JobPost {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long postId;

    private String postProfile;
    private String postDesc;
    private int reqExperience;

    // ✅ Proper relational mapping for list of strings
    @ElementCollection
    @CollectionTable(
        name = "job_tech_stack",          // table name for tech stack
        joinColumns = @JoinColumn(name = "post_id") // foreign key
    )
    @Column(name = "tech") // column name for each tech
    private List<String> postTechStack;
    
  
    @Column(name="created_by",nullable = false)
    String createdBy;
}

