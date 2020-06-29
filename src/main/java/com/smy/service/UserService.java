package com.smy.service;

import com.smy.vo.User;

public interface UserService {

	User findByName(String name);
	
	User findById(Integer id);
}
