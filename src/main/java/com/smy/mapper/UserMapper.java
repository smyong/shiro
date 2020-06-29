package com.smy.mapper;

import com.smy.vo.User;

public interface UserMapper {

	User findByName(String name);
	
	User findById(Integer id);
}
