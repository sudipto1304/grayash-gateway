package com.grayash.gateway.repository;

import javax.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.grayash.gateway.entity.UserEntity;

@Repository
@Transactional
public interface UserRepository extends JpaRepository<UserEntity, String> {

    UserEntity findTopByCustomerId(String customerId);

}
