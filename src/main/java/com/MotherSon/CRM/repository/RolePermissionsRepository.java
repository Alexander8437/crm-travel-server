package com.MotherSon.CRM.repository;

import org.springframework.stereotype.Repository;

import com.MotherSon.CRM.models.RolePermission;

import org.springframework.data.jpa.repository.JpaRepository;
 
@Repository
public interface RolePermissionsRepository extends JpaRepository<RolePermission, Long> {
	
}
 
 
