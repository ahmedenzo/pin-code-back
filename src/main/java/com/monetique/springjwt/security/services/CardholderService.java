package com.monetique.springjwt.security.services;

import com.monetique.springjwt.models.Cardholder;
import com.monetique.springjwt.repository.CardholderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Optional;

@Service
public class CardholderService {

    @Autowired
    private CardholderRepository cardholderRepository;

    @Autowired
    private InfobipSmsService infobipSmsService;

    public boolean verifyCardholder(String cardNumber, String cin, String phoneNumber, String expirationDate) {
        Optional<Cardholder> cardholder = cardholderRepository.findByCardNumberAndCinAndPhoneNumberAndExpirationDate(
                cardNumber, cin, phoneNumber,expirationDate
        );

        return cardholder.isPresent() && cardholder.get().getExpirationDate().equals(expirationDate);
    }

    public void sendPin(String phoneNumber) {
        // Retrieve the Cardholder from the database
        Optional<Cardholder> cardholder = cardholderRepository.findPinByPhoneNumber(phoneNumber);

        // If the cardholder exists, send the PIN via SMS
        if (cardholder.isPresent()) {
            String pin = cardholder.get().getPin();
            try {
                infobipSmsService.sendSms(phoneNumber, "Your card PIN is: " + pin);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            // Handle the case where the cardholder does not exist
            System.err.println("Cardholder with phone number " + phoneNumber + " not found.");
        }
    }
}
