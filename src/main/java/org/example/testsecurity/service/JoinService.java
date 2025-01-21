package org.example.testsecurity.service;

import org.example.testsecurity.dto.JoinDTO;
import org.example.testsecurity.entity.UserEntity;
import org.example.testsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public void joinProcess(JoinDTO joinDTO) {

		// db에 이미 동일한 username을 가진 회원이 존재하는지?
		boolean isUser = userRepository.existsByUsername(joinDTO.getUsername());
		if (isUser) {
			return;
		}

		UserEntity data = new UserEntity();
		data.setUsername(joinDTO.getUsername());
		data.setPassword(bCryptPasswordEncoder.encode(joinDTO.getPassword()));
		data.setRole("ROLE_ADMIN");

		userRepository.save(data);
	}
}
