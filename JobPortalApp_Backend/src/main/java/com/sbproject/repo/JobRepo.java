package com.sbproject.repo;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.sbproject.model.JobPost;

import java.util.List;
import java.util.Optional;

@Repository
public interface JobRepo extends JpaRepository<JobPost, Long> {

    List<JobPost> findByPostProfileContainingIgnoreCaseAndPostDescContainingIgnoreCase(
            String profileKeyword, String descKeyword);

    List<JobPost> findByCreatedByIgnoreCase(String email);

    Optional<JobPost> findByPostId(Long postId);
}


