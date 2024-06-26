package com.monetique.springjwt.security.services;

import com.monetique.springjwt.models.Cardholder;
import com.monetique.springjwt.repository.CardholderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Random;

@Service
public class RandomCardholderService {

    @Autowired
    private CardholderRepository cardholderRepository;

    private static final String CHARACTERS = "0123456789";
    private static final int CARD_NUMBER_LENGTH = 16;
    private static final int CIN_LENGTH = 8;
    private static final int PIN_LENGTH = 4;
    private static final Random RANDOM = new Random();

    public Cardholder generateRandomCardholder() {
        String cardNumber = generateRandomString(CARD_NUMBER_LENGTH);
        String cin = generateRandomString(CIN_LENGTH);
        String phoneNumber = generateRandomPhoneNumber();
        String pin = generateRandomString(PIN_LENGTH);

        Cardholder cardholder = new Cardholder(null, cardNumber, cin, phoneNumber, pin);
        return cardholderRepository.save(cardholder);
    }

    private String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARACTERS.charAt(RANDOM.nextInt(CHARACTERS.length())));
        }
        return sb.toString();
    }

    private String generateRandomPhoneNumber() {
        // Generate random phone number with the format 216xxxxxxx
        return "216" + String.format("%07d", RANDOM.nextInt(10000000));
    }
}