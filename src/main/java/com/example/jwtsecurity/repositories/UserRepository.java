package com.example.jwtsecurity.repositories;


import com.example.jwtsecurity.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    public User findByUsername(String username);
}
