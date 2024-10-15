package com.MotherSon.CRM.repository;
import org.springframework.stereotype.Repository;

import com.MotherSon.CRM.rolepermission.RolePermissionActions;

import org.springframework.data.jpa.repository.JpaRepository;
 
@Repository
public interface RolePermissionsActionsRepository extends JpaRepository<RolePermissionActions, Long> {
	
}
 
