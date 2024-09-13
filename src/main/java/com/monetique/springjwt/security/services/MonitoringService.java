package com.monetique.springjwt.security.services;


import com.monetique.springjwt.Exception.ResourceNotFoundException;
import com.monetique.springjwt.models.HttpMethodEnum;
import com.monetique.springjwt.models.User;
import com.monetique.springjwt.repository.UserRepository;
import com.monetique.springjwt.models.ApiRequestLog;
import com.monetique.springjwt.models.UserSession;
import com.monetique.springjwt.payload.response.ApiReportResponse;
import com.monetique.springjwt.repository.ApiRequestLogRepository;
import com.monetique.springjwt.repository.UserSessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class MonitoringService {

    @Autowired
    private ApiRequestLogRepository apiRequestLogRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserSessionRepository userSessionRepository;

    public UserSession getCurrentSession(String username) {
        // Fetch session from the repository or session service by username
        UserSession session = userSessionRepository.findCurrentSessionByUsername(username);

        if (session == null) {
            throw new ResourceNotFoundException("Session", "username", username);
        }

        return session;
    }


    // Generate report for all API calls by a user
    public ApiReportResponse generateUserReport(Long userId, LocalDateTime startDate, LocalDateTime endDate) {
        List<ApiRequestLog> logs = apiRequestLogRepository.findBySession_User_Id(userId).stream()
                .filter(log -> log.getTimestamp().isAfter(startDate) && log.getTimestamp().isBefore(endDate))
                .collect(Collectors.toList());

        long totalRequests = logs.size();
        long successRequests = logs.stream().filter(log -> log.getStatusCode() >= 200 && log.getStatusCode() < 300).count();
        long failedRequests = totalRequests - successRequests;

        return new ApiReportResponse(totalRequests, successRequests, failedRequests, logs);
    }

    // Generate report for all API calls by all users of an admin
    public ApiReportResponse generateAdminReport(Long adminId, LocalDateTime startDate, LocalDateTime endDate) {
        List<ApiRequestLog> logs = apiRequestLogRepository.findBySession_User_Admin_Id(adminId).stream()
                .filter(log -> log.getTimestamp().isAfter(startDate) && log.getTimestamp().isBefore(endDate))
                .collect(Collectors.toList());

        long totalRequests = logs.size();
        long successRequests = logs.stream().filter(log -> log.getStatusCode() >= 200 && log.getStatusCode() < 300).count();
        long failedRequests = totalRequests - successRequests;

        return new ApiReportResponse(totalRequests, successRequests, failedRequests, logs);
    }

    // Generate report for session durations
    public Map<Long, Long> generateSessionDurations(Long userId) {
        List<UserSession> sessions = userSessionRepository.findByUser_Id(userId);

        return sessions.stream().collect(Collectors.toMap(
                UserSession::getId,
                session -> session.getLogoutTime().isAfter(session.getLoginTime()) ?
                        session.getLogoutTime().atZone(ZoneId.systemDefault()).toEpochSecond() -
                                session.getLoginTime().atZone(ZoneId.systemDefault()).toEpochSecond() : 0
        ));
    }

    // Fetch logs by admin ID
    public List<ApiRequestLog> getLogsByAdminId(Long adminId) {
        return apiRequestLogRepository.findBySession_User_Admin_Id(adminId);
    }

    // Fetch logs by user ID
    public List<ApiRequestLog> getLogsByUserId(Long userId) {
        return apiRequestLogRepository.findBySession_User_Id(userId);
    }

    // Fetch active sessions (users currently logged in)
    public List<UserSession> getActiveSessions() {
        return userSessionRepository.findByLogoutTimeIsNull();
    }

    // Fetch all sessions
    public List<UserSession> getAllSessions() {
        return userSessionRepository.findAll();
    }




    public void logRequest(UserSession session, String requestPath, HttpMethodEnum method, int statusCode, long responseTimeMs) {
        ApiRequestLog requestLog = new ApiRequestLog();
        requestLog.setSession(session);  // Correctly set the UserSession object
        requestLog.setRequestPath(requestPath);
        requestLog.setMethod(method);  // Assuming HttpMethodEnum is defined correctly
        requestLog.setStatusCode(statusCode);
        requestLog.setResponseTimeMs(responseTimeMs);
        requestLog.setTimestamp(LocalDateTime.now());

        // Save the log to the database
        apiRequestLogRepository.save(requestLog);
    }




    // Method to start a new session when the user logs in
    public UserSession startSession(Long userId) {
        // Retrieve the user from the repository
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Create a new session for the user
        UserSession session = new UserSession();
        session.setUser(user);
        session.setLoginTime(LocalDateTime.now());

        // Save the session to the repository
        return userSessionRepository.save(session);
    }

}
