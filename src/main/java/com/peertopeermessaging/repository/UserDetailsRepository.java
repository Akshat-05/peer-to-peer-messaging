package com.peertopeermessaging.repository;

import com.peertopeermessaging.entity.UserDetails;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserDetailsRepository extends CrudRepository<UserDetails, String> {
}
