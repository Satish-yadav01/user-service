package com.example.userservice.repository;

import com.example.userservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u.enabled FROM User u WHERE u.id = :userId")
    Optional<Boolean> findEnabledById(@Param("userId") Long userId);
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
}
