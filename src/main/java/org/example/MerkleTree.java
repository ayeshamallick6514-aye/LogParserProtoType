package org.example;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class MerkleTree {
    private List<String> transactions;

    public MerkleTree(List<String> transactions) {
        this.transactions = transactions;
    }

    public String getMerkleRoot() {
        if (transactions == null || transactions.isEmpty()) {
            return "0x0000000000000000000000000000000000000000000000000000000000000000";
        }
        List<String> previousLevel = new ArrayList<>(transactions);

        while (previousLevel.size() > 1) {
            List<String> currentLevel = new ArrayList<>();
            for (int i = 0; i < previousLevel.size(); i += 2) {
                String left = previousLevel.get(i);
                String right = (i + 1 < previousLevel.size()) ? previousLevel.get(i + 1) : left;
                currentLevel.add(sha256(left + right));
            }
            previousLevel = currentLevel;
        }
        return "0x" + previousLevel.get(0);
    }

    private static String sha256(String base) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(base.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception ex) {
            return "0000000000000000000000000000000000000000000000000000000000000000";
        }
    }
}