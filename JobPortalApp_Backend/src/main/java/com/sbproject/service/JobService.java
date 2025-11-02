package com.sbproject.service;





import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sbproject.*;
import com.sbproject.model.JobPost;
import com.sbproject.repo.JobRepo;


@Service
public class JobService {

    @Autowired
    private JobRepo repo;

    public List<JobPost> getAllJobPosts() {
        return repo.findAll();
    }

    public JobPost addJobPost(JobPost jobPost) {
        return repo.save(jobPost);
    }

    public JobPost getJob(Long postId) {
        return repo.findByPostId(postId).orElse(new JobPost());
    }

    public void updateJob(JobPost jobpost) {
        JobPost existing = repo.findByPostId(jobpost.getPostId())
                .orElseThrow(() -> new RuntimeException("Job not found"));
        existing.setPostProfile(jobpost.getPostProfile());
        existing.setPostDesc(jobpost.getPostDesc());
        existing.setReqExperience(jobpost.getReqExperience());
        existing.setPostTechStack(jobpost.getPostTechStack());
        repo.save(existing);
    }

    public void deleteJob(Long postId) {
        repo.deleteById(postId);
    }

    public void updateJobByAdmin(Long id, JobPost updatedJob, String adminEmail) {
        JobPost existing = repo.findByPostId(id)
                .orElseThrow(() -> new RuntimeException("Job not found"));
        if (!existing.getCreatedBy().equals(adminEmail)) {
            throw new RuntimeException("Forbidden: You can edit only your own jobs");
        }
        existing.setPostProfile(updatedJob.getPostProfile());
        existing.setPostDesc(updatedJob.getPostDesc());
        existing.setReqExperience(updatedJob.getReqExperience());
        existing.setPostTechStack(updatedJob.getPostTechStack());
        repo.save(existing);
    }

    public List<JobPost> findByCreatedBy(String email) {
        return repo.findByCreatedByIgnoreCase(email);
    }

    public List<JobPost> search(String keyword) {
        return repo.findByPostProfileContainingIgnoreCaseAndPostDescContainingIgnoreCase(keyword, keyword);
    }

    public void deleteJobByAdmin(Long id, String adminEmail) {
        JobPost existing = repo.findByPostId(id)
                .orElseThrow(() -> new RuntimeException("Job not found"));
        if (!existing.getCreatedBy().equals(adminEmail)) {
            throw new RuntimeException("Forbidden: You can delete only your own jobs");
        }
        repo.delete(existing);
    }

    public Optional<JobPost> findById(Long id) {
        return repo.findByPostId(id);
    }

	public void load() {
		// TODO Auto-generated method stub
		repo.findAll();
		
	}
}
