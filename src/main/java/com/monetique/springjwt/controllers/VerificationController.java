package com.monetique.springjwt.controllers;


import com.monetique.springjwt.payload.request.CardholderVerificationRequest;
import com.monetique.springjwt.payload.request.OtpValidationRequest;
import com.monetique.springjwt.payload.response.MessageResponse;
import com.monetique.springjwt.security.services.CardholderService;
import com.monetique.springjwt.security.services.OtpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class VerificationController {

    @Autowired
    private CardholderService cardholderService;

    @Autowired
    private OtpService otpService;

    @PostMapping("/verifyCardholder")
    public ResponseEntity<?> verifyCardholder(@RequestBody CardholderVerificationRequest request) {
        boolean isValid = cardholderService.verifyCardholder(request.getCardNumber(), request.getCin(), request.getPhoneNumber());

        if (isValid) {
            String otp = otpService.generateOtp(request.getPhoneNumber());
            otpService.sendOtp(request.getPhoneNumber(), otp);
            return ResponseEntity.ok(new MessageResponse("OTP sent successfully!"));
        } else {
            return ResponseEntity.badRequest().body(new MessageResponse("Invalid cardholder information!"));
        }
    }

    @PostMapping("/validateOtp")
    public ResponseEntity<?> validateOtp(@RequestBody OtpValidationRequest request) {
        boolean isValidOtp = otpService.validateOtp(request.getPhoneNumber(), request.getOtp());

        if (isValidOtp) {
            cardholderService.sendPin(request.getPhoneNumber());
            return ResponseEntity.ok(new MessageResponse("OTP validated successfully, PIN sent!"));
        } else {
            return ResponseEntity.badRequest().body(new MessageResponse("Invalid OTP!"));
        }
    }
}