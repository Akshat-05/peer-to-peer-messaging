package com.peertopeermessaging.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "user_details")
public class UserDetails {

	@Id
	private String username;
	private String password;

}