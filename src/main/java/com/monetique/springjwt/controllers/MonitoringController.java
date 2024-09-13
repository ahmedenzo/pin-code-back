package com.monetique.springjwt.controllers;
import com.monetique.springjwt.models.ApiRequestLog;
import com.monetique.springjwt.models.UserSession;
import com.monetique.springjwt.payload.response.ApiReportResponse;
import com.monetique.springjwt.payload.response.MessageResponse;
import com.monetique.springjwt.security.services.MonitoringService;
import com.monetique.springjwt.security.services.UserDetailsImpl;
import com.monetique.springjwt.Exception.AccessDeniedException;
import com.monetique.springjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api/monitor")
public class MonitoringController {

    @Autowired
    private MonitoringService monitoringService;



    // API to track all sessions for a specific admin and their users - only accessible by Super Admin
    @GetMapping("/trackAdmin/{adminId}")
    public ResponseEntity<?> trackAdminUsage(@PathVariable Long adminId) {
        // Check if the currently authenticated user is a Super Admin
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl currentUserDetails = (UserDetailsImpl) authentication.getPrincipal();

        if (!currentUserDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_SUPER_ADMIN"))) {

            throw new AccessDeniedException("Error: Only Super Admin can access this monitoring API.");
        }

        List<ApiRequestLog> logs = monitoringService.getLogsByAdminId(adminId);
        return ResponseEntity.ok(logs);
    }

    // API to track all sessions for a specific user - only accessible by Super Admin
    @GetMapping("/trackUser/{userId}")
    public ResponseEntity<?> trackUserUsage(@PathVariable Long userId) {
        // Check if the currently authenticated user is a Super Admin
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl currentUserDetails = (UserDetailsImpl) authentication.getPrincipal();

        if (!currentUserDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_SUPER_ADMIN"))) {

            throw new AccessDeniedException("Error: Only Super Admin can access this monitoring API.");
        }

        List<ApiRequestLog> logs = monitoringService.getLogsByUserId(userId);
        return ResponseEntity.ok(logs);
    }

    // API to track active sessions (users currently logged in) - only accessible by Super Admin
    @GetMapping("/activeSessions")
    public ResponseEntity<?> trackActiveSessions() {
        // Check if the currently authenticated user is a Super Admin
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl currentUserDetails = (UserDetailsImpl) authentication.getPrincipal();

        if (!currentUserDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_SUPER_ADMIN"))) {

            throw new AccessDeniedException("Error: Only Super Admin can access this monitoring API.");
        }

        List<UserSession> activeSessions = monitoringService.getActiveSessions();
        return ResponseEntity.ok(activeSessions);
    }

    // API to track all sessions across the system - only accessible by Super Admin
    @GetMapping("/allSessions")
    public ResponseEntity<?> trackAllSessions() {
        // Check if the currently authenticated user is a Super Admin
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl currentUserDetails = (UserDetailsImpl) authentication.getPrincipal();

        if (!currentUserDetails.getAuthorities().stream().anyMatch(auth -> auth.getAuthority().equals("ROLE_SUPER_ADMIN"))) {

            throw new AccessDeniedException("Error: Only Super Admin can access this monitoring API.");
        }

        List<UserSession> allSessions = monitoringService.getAllSessions();
        return ResponseEntity.ok(allSessions);
    }
    // Super Admin can generate a report for any user
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/userReport")
    public ResponseEntity<ApiReportResponse> getUserReport(@RequestParam Long userId,
                                                           @RequestParam String startDate,
                                                           @RequestParam String endDate) {
        LocalDateTime start = LocalDateTime.parse(startDate);
        LocalDateTime end = LocalDateTime.parse(endDate);

        ApiReportResponse report = monitoringService.generateUserReport(userId, start, end);
        return ResponseEntity.ok(report);
    }

    // Super Admin can generate a report for all users under a specific admin
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/adminReport")
    public ResponseEntity<ApiReportResponse> getAdminReport(@RequestParam Long adminId,
                                                            @RequestParam String startDate,
                                                            @RequestParam String endDate) {
        LocalDateTime start = LocalDateTime.parse(startDate);
        LocalDateTime end = LocalDateTime.parse(endDate);

        ApiReportResponse report = monitoringService.generateAdminReport(adminId, start, end);
        return ResponseEntity.ok(report);
    }

    // Super Admin can generate a session duration report for a user
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @GetMapping("/sessionDuration")
    public ResponseEntity<?> getSessionDurations(@RequestParam Long userId) {
        return ResponseEntity.ok(monitoringService.generateSessionDurations(userId));
    }
}
