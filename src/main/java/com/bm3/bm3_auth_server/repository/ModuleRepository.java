package com.bm3.bm3_auth_server.repository;

import com.bm3.bm3_auth_server.entity.Module;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ModuleRepository extends JpaRepository<Module, Long> {
}
