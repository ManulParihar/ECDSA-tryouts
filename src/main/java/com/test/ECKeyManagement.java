package com.test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.web3j.crypto.*;
import org.web3j.utils.Numeric;

public class ECKeyManagement {

	public static String compressPublicKey(BigInteger pubKey) {
		String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
		String pubKeyHex = pubKey.toString(16);
		String pubKeyX = pubKeyHex.substring(0, 64);

		return pubKeyYPrefix + pubKeyX;
	}

    public static String signMessage(String message, ECKeyPair ecKeyPair) {
        byte[] hash = message.getBytes(StandardCharsets.UTF_8);
        Sign.SignatureData signature = Sign.signPrefixedMessage(hash, ecKeyPair);
        String r = Numeric.toHexString(signature.getR());
        String s = Numeric.toHexString(signature.getS()).substring(2);
        String v = Numeric.toHexString(signature.getV()).substring(2);
        System.out.println(r + "    " + s + "    " + v);
        return r + s + v;
    }

    public static ECKeyPair generateECKeyPair() throws Exception {
        try {
            // Generate a random private key
            BigInteger privateKey = Keys.createEcKeyPair().getPrivateKey();
            BigInteger publicKey = Sign.publicKeyFromPrivate(privateKey);

            return new ECKeyPair(privateKey, publicKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String deriveAddress(BigInteger publicKey) {
        return "0x" + Keys.getAddress((publicKey));
    }

	public static void main(String[] args) throws Exception {
		// Generate a random private key
		ECKeyPair keyPair = generateECKeyPair();
        BigInteger publicKey = keyPair.getPublicKey();
        BigInteger privateKey = keyPair.getPrivateKey();
        String address = deriveAddress(publicKey);

		System.out.println("Private key (256 bits): " + publicKey.toString(16));
		System.out.println("Public key (512 bits): " + privateKey.toString(16));
		System.out.println("Public key (compressed): " + compressPublicKey(publicKey));
        System.out.println("Address: " + address);

		// Sign message
		String msg = "TEST";
        String signedMessage = signMessage(msg, keyPair);
        System.out.println("SignedMessage: " + signedMessage);
	}
}
