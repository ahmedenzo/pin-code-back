package com.monetique.springjwt.repository;



import com.monetique.springjwt.models.ApiRequestLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ApiRequestLogRepository extends JpaRepository<ApiRequestLog, Long> {
    List<ApiRequestLog> findBySession_User_Id(Long userId);

    List<ApiRequestLog> findBySession_User_Admin_Id(Long adminId);
}
