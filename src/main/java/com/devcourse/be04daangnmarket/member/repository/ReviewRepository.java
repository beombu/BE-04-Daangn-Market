package com.devcourse.be04daangnmarket.member.repository;

import com.devcourse.be04daangnmarket.member.domain.Review;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ReviewRepository extends JpaRepository<Review, Long> {
}
